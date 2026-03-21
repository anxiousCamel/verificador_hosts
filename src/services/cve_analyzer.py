"""
# src/services/cve_analyzer.py — Verificação de vulnerabilidades via CPE + faixa de versão

## Descrição
Módulo responsável por correlacionar banners de serviços com CVEs conhecidos,
usando dados da NVD (National Vulnerability Database) e matching por CPE.

Estratégia para minimizar falsos positivos:
1. Extrai (produto, versão) do banner via regex
2. Normaliza para o vocabulário NVD (vendor, product) via mapa de aliases
3. Consulta índice CPE local (construído a partir dos JSONs NVD)
4. Compara versão usando semver: match exato, faixa (start/end), ou qualquer versão

## Otimizações
- Cache em disco (pickle) do índice CPE (~14MB) para startup instantâneo
- LRU cache na construção do índice (evita rebuilds em sequência)
- Filtro por anos recentes (NVD_INDEX_MAX_YEARS)
- Filtro por tipo de CPE (aplicação/OS/hardware)
- Usa orjson quando disponível (2-5x mais rápido que json stdlib)

## Variáveis de ambiente
- `NVD_DIR`: Diretório dos JSONs NVD (padrão: "nvd_data")
- `NVD_INDEX_PKL`: Caminho do cache pickle (padrão: nvd_data/nvd_index.pkl)
- `NVD_INDEX_MAX_YEARS`: Anos recentes a indexar (padrão: 5)
- `CPE_PART_ALLOWED`: Filtro de tipo — "a" (app), "o" (OS), "h" (hw), "" (todos)

## Requisitos
- packaging>=24.0

Camada: services (sem dependências de projeto)
"""

from __future__ import annotations

import os
import re
import gzip
import pickle
from typing import Dict, List, Tuple, Iterable, Optional
from functools import lru_cache
from datetime import datetime
from packaging.version import Version, InvalidVersion

try:
    import orjson
    def _load_json(f):
        """Carrega JSON usando orjson (mais rápido para arquivos grandes)."""
        return orjson.loads(f.read())
except ImportError:
    import json
    def _load_json(f):
        """Carrega JSON usando stdlib."""
        return json.load(f)


# ==============================
# Configuração
# ==============================

NVD_DIR = os.environ.get("NVD_DIR", "nvd_data")
NVD_INDEX_PKL = os.environ.get("NVD_INDEX_PKL", os.path.join(NVD_DIR, "nvd_index.pkl"))
NVD_INDEX_MAX_YEARS = int(os.environ.get("NVD_INDEX_MAX_YEARS", "5"))
CPE_PART_ALLOWED = os.environ.get("CPE_PART_ALLOWED", "a")


# ==============================
# Normalização de produtos
# ==============================

_PRODUCT_ALIASES: Dict[str, Tuple[str, str]] = {
    "openssh":       ("openbsd", "openssh"),
    "apache":        ("apache", "http_server"),
    "httpd":         ("apache", "http_server"),
    "nginx":         ("nginx", "nginx"),
    "lighttpd":      ("lighttpd", "lighttpd"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "mysql":         ("oracle", "mysql"),
    "mariadb":       ("mariadb", "mariadb"),
    "postgresql":    ("postgresql", "postgresql"),
    "redis":         ("redis", "redis"),
    "mongodb":       ("mongodb", "mongodb"),
    "openssl":       ("openssl", "openssl"),
    "proftpd":       ("proftpd_project", "proftpd"),
    "pureftpd":      ("pureftpd", "pure-ftpd"),
    "pure-ftpd":     ("pureftpd", "pure-ftpd"),
    "vsftpd":        ("vsftpd_project", "vsftpd"),
    "ftpd":          ("openbsd", "ftpd"),
    "opensmtpd":     ("openbsd", "opensmtpd"),
    "postfix":       ("postfix", "postfix"),
    "dovecot":       ("dovecot", "dovecot"),
    "exim":          ("exim", "exim"),
}


def normalize_product(name: str) -> Tuple[str, str]:
    """
    Converte nome de banner para (vendor, product) conforme taxonomia NVD.

    Primeiro tenta match por alias conhecido, depois usa o nome como
    vendor e product (fallback genérico).
    """
    base = (name or "").strip().lower()
    compact = base.replace("-", "").replace("_", "")
    for alias, vendor_product in _PRODUCT_ALIASES.items():
        if compact.startswith(alias.replace("-", "")):
            return vendor_product
    normalized = base.replace(" ", "_")
    return (normalized, normalized)


def extract_product_version(banner: str) -> Optional[Tuple[str, str]]:
    """
    Extrai (produto, versão) de um banner de serviço usando fingerprinting avançado.

    Usa uma cadeia de regexes especializados, ordenados do mais específico ao
    mais genérico.

    Args:
        banner: String do banner.

    Returns:
        Tupla (produto, versão) ou None se não reconhecido.
    """
    if not banner:
        return None

    text = banner.strip()

    m = re.search(r'OpenSSH[_\s](\d+\.\d+[a-z0-9]*)', text, re.IGNORECASE)
    if m:
        return ("openssh", m.group(1))

    m = re.search(r'(?:Pro)?FTPd?\s+v?(\d+\.\d+(?:\.\d+)?[a-z]?)', text, re.IGNORECASE)
    if m:
        product = "proftpd" if "proftp" in text.lower() else "vsftpd" if "vsftp" in text.lower() else "ftpd"
        return (product, m.group(1))

    m = re.search(r'Pure-FTPd', text, re.IGNORECASE)
    if m:
        ver_m = re.search(r'Pure-FTPd\s+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
        return ("pure-ftpd", ver_m.group(1) if ver_m else None)

    m = re.search(r'Microsoft-IIS[/\s]+(\d+\.\d+)', text, re.IGNORECASE)
    if m:
        return ("microsoft-iis", m.group(1))

    m = re.search(r'Apache(?:/|\s+HTTP\s+Server\s*/?\s*)(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("apache", m.group(1))

    m = re.search(r'nginx[/\s]+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("nginx", m.group(1))

    m = re.search(r'lighttpd[/\s]+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("lighttpd", m.group(1))

    m = re.search(r'(\d+\.\d+\.\d+)(?:\S*?)[- ]?MariaDB', text, re.IGNORECASE)
    if m:
        return ("mariadb", m.group(1))
    m = re.search(r'MySQL\s*[/\s]?(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("mysql", m.group(1))

    m = re.search(r'PostgreSQL\s+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("postgresql", m.group(1))

    m = re.search(r'[Rr]edis(?:\s+version|_version)?[:\s]+(\d+\.\d+(?:\.\d+)?)', text)
    if m:
        return ("redis", m.group(1))

    m = re.search(r'Exim\s+(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("exim", m.group(1))

    m = re.search(r'Postfix(?:\s+(\d+\.\d+(?:\.\d+)?))?', text, re.IGNORECASE)
    if m:
        return ("postfix", m.group(1))

    m = re.search(r'Dovecot(?:\s+(\d+\.\d+(?:\.\d+)?))?', text, re.IGNORECASE)
    if m:
        return ("dovecot", m.group(1))

    m = re.search(r'OpenSSL[/\s]+(\d+\.\d+\.\d+[a-z]*)', text, re.IGNORECASE)
    if m:
        return ("openssl", m.group(1))

    m = re.search(r'MongoDB\s+(?:version\s+)?v?(\d+\.\d+(?:\.\d+)?)', text, re.IGNORECASE)
    if m:
        return ("mongodb", m.group(1))

    # Padrões genéricos (fallback)
    m = re.search(
        r'([A-Za-z0-9\-_]+)[/\s]v?([0-9]+(?:\.[0-9a-z]+){0,3}(?:[-_][0-9a-z\.]+)?)',
        text, flags=re.IGNORECASE,
    )
    if m:
        return (m.group(1).strip().lower(), m.group(2))

    m = re.search(r'([A-Za-z0-9\-_]+)_([0-9]+[0-9a-zA-Z\.\-]*)', text)
    if m:
        return (m.group(1).strip().lower(), m.group(2))

    return None


# ==============================
# CPE e comparação de versões
# ==============================

def parse_cpe23(cpe_uri: str) -> Optional[Dict[str, str]]:
    """
    Faz parsing de uma URI CPE 2.3 para seus componentes.

    Formato: "cpe:2.3:part:vendor:product:version:update:..."
    """
    parts = (cpe_uri or "").split(":")
    if len(parts) < 6:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
    }


def _to_semver(version_str: Optional[str]) -> Optional[Version]:
    """
    Converte string de versão para packaging.version.Version.

    Trata versões não-PEP440 (ex: "8.2p1") extraindo apenas a parte numérica.
    """
    if not version_str:
        return None
    try:
        return Version(version_str)
    except InvalidVersion:
        match = re.match(r'^([0-9]+(?:\.[0-9]+){0,3})', version_str)
        if match:
            try:
                return Version(match.group(1))
            except InvalidVersion:
                return None
        return None


def version_in_range(target: str, rules: Dict[str, Optional[str]]) -> bool:
    """
    Verifica se uma versão está dentro de uma faixa NVD.

    Regras suportadas:
    - versionStartIncluding / versionStartExcluding
    - versionEndIncluding / versionEndExcluding
    """
    target_ver = _to_semver(target)
    if target_ver is None:
        return False

    start_inc = _to_semver(rules.get("versionStartIncluding"))
    start_exc = _to_semver(rules.get("versionStartExcluding"))
    end_inc = _to_semver(rules.get("versionEndIncluding"))
    end_exc = _to_semver(rules.get("versionEndExcluding"))

    if start_inc and target_ver < start_inc:
        return False
    if start_exc and target_ver <= start_exc:
        return False
    if end_inc and target_ver > end_inc:
        return False
    if end_exc and target_ver >= end_exc:
        return False
    return True


def versions_equal(v1: str, v2: str) -> bool:
    """Compara duas versões com tolerância a sufixos não-semânticos."""
    a, b = _to_semver(v1), _to_semver(v2)
    if a is not None and b is not None:
        return a == b
    return (v1 or "").strip() == (v2 or "").strip()


# ==============================
# Cache do índice em disco
# ==============================

def _load_index_cache() -> Optional[Dict[Tuple[str, str], List[dict]]]:
    """Carrega índice CPE do cache pickle, se existir e for válido."""
    try:
        if os.path.exists(NVD_INDEX_PKL):
            with open(NVD_INDEX_PKL, "rb") as f:
                return pickle.load(f)
    except Exception:
        return None
    return None


def _save_index_cache(index: Dict[Tuple[str, str], List[dict]]) -> None:
    """Salva índice CPE em cache pickle para reutilização."""
    try:
        os.makedirs(os.path.dirname(NVD_INDEX_PKL) or ".", exist_ok=True)
        with open(NVD_INDEX_PKL, "wb") as f:
            pickle.dump(index, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass


# ==============================
# Iteração de nós CPE (recursiva via stack)
# ==============================

def _iter_cpe_matches(nodes: List[dict]):
    """
    Percorre a árvore de nós de configuração NVD, gerando CPE matches.

    Usa stack iterativo (sem recursão) para evitar stack overflow.
    """
    if not nodes:
        return
    stack = list(nodes)
    while stack:
        node = stack.pop()
        for match in node.get("cpe_match", []) or []:
            yield match
        children = node.get("children") or []
        if children:
            stack.extend(children)


# ==============================
# Construção do índice CPE
# ==============================

def _extract_year(filename: str) -> Optional[int]:
    """Extrai ano de um nome de arquivo NVD."""
    match = re.search(r'(\d{4})', filename or "")
    return int(match.group(1)) if match else None


def _open_nvd_file(path: str):
    """Abre arquivo NVD (suporta .json e .json.gz)."""
    if path.endswith(".gz"):
        return gzip.open(path, "rb")
    return open(path, "rb")


def _parse_cve_item(item: dict) -> Tuple[str, List[dict]]:
    """
    Extrai CVE ID e nós de configuração de um item NVD.

    Suporta ambos os formatos NVD (1.1 e 2.0).
    """
    if "cve" in item and "CVE_data_meta" in item.get("cve", {}):
        cve_id = item["cve"]["CVE_data_meta"].get("ID", "")
        nodes = item.get("configurations", {}).get("nodes", [])
    else:
        vuln = item.get("cve") or item.get("vuln") or {}
        cve_id = (
            vuln.get("id")
            or vuln.get("CVE_data_meta", {}).get("ID", "")
            or item.get("id", "")
        )
        nodes = item.get("configurations", {}).get("nodes", [])
    return cve_id, nodes


@lru_cache(maxsize=1)
def build_cpe_index(nvd_dir: str = NVD_DIR) -> Dict[Tuple[str, str], List[dict]]:
    """
    Constrói índice CPE a partir dos JSONs NVD.

    Estrutura: { (vendor, product): [ { cve, anyVersion, exactVersion?, versionRules } ] }

    O índice permite lookup O(1) por (vendor, product).

    Otimizações:
    - Cache pickle em disco (evita re-parsing dos JSONs a cada execução)
    - Filtro por anos recentes (NVD_INDEX_MAX_YEARS)
    - Filtro por tipo de CPE (CPE_PART_ALLOWED)
    """
    cached = _load_index_cache()
    if cached:
        return cached

    index: Dict[Tuple[str, str], List[dict]] = {}
    if not os.path.exists(nvd_dir):
        _save_index_cache(index)
        return index

    current_year = datetime.now().year
    min_year = current_year - NVD_INDEX_MAX_YEARS
    part_filter = (CPE_PART_ALLOWED or "").strip().lower()

    for root, _, files in os.walk(nvd_dir):
        for filename in files:
            if not (filename.endswith(".json") or filename.endswith(".json.gz")):
                continue

            year = _extract_year(filename)
            if year and year < min_year:
                continue

            filepath = os.path.join(root, filename)
            try:
                with _open_nvd_file(filepath) as f:
                    data = _load_json(f)
            except Exception:
                continue

            items = data.get("CVE_Items") or data.get("vulnerabilities")
            if not items:
                continue

            for item in items:
                cve_id, nodes = _parse_cve_item(item)

                for cpe_match in _iter_cpe_matches(nodes):
                    if not cpe_match.get("vulnerable", False):
                        continue

                    cpe_uri = cpe_match.get("cpe23Uri") or cpe_match.get("criteria") or ""
                    cpe = parse_cpe23(cpe_uri)
                    if not cpe:
                        continue

                    if part_filter and cpe.get("part") != part_filter:
                        continue

                    key = (cpe["vendor"], cpe["product"])

                    version_rules = {
                        "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                        "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                        "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                        "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                    }

                    is_any_version = cpe["version"] in ("*", "-", "", None)
                    has_range = any(version_rules.values())

                    entry = {
                        "cve": cve_id,
                        "anyVersion": is_any_version,
                        "versionRules": version_rules,
                    }

                    if not is_any_version and not has_range:
                        entry["exactVersion"] = cpe["version"]

                    index.setdefault(key, []).append(entry)

    _save_index_cache(index)
    return index


# ==============================
# Consulta de vulnerabilidades por CPE
# ==============================

def check_vulnerabilities_by_cpe(
    vendor: str, product: str, version: Optional[str]
) -> Tuple[List[str], List[str]]:
    """
    Consulta CVEs para um (vendor, product, version) específico.

    Classificação:
    - **Confirmadas**: versão dentro da faixa, match exato, ou CVE afeta todas.
    - **Suspeitas**: produto casa mas não temos versão para confirmar.

    Returns:
        Tupla (confirmadas, suspeitas) — listas de CVE IDs.
    """
    index = build_cpe_index()
    entries = index.get((vendor, product), [])

    confirmed: List[str] = []
    suspected: List[str] = []

    for entry in entries:
        cve_id = entry["cve"]

        if entry.get("anyVersion"):
            if version:
                confirmed.append(cve_id)
            else:
                suspected.append(cve_id)
            continue

        exact = entry.get("exactVersion")
        if exact is not None:
            if version and versions_equal(version, exact):
                confirmed.append(cve_id)
            elif not version:
                suspected.append(cve_id)
            continue

        rules = entry.get("versionRules") or {}
        if version and any(rules.values()) and version_in_range(version, rules):
            confirmed.append(cve_id)
        elif not version:
            suspected.append(cve_id)

    return sorted(set(confirmed)), sorted(set(suspected))


# ==============================
# API pública
# ==============================

def carregar_base_local_cves(diretorio: str = NVD_DIR, usar_cache: bool = True):
    """
    Garante que o índice CPE está carregado.

    Mantida por compatibilidade. Se usar_cache=False, força rebuild do índice.
    """
    if not usar_cache:
        build_cpe_index.cache_clear()
        try:
            if os.path.exists(NVD_INDEX_PKL):
                os.remove(NVD_INDEX_PKL)
        except Exception:
            pass
    build_cpe_index(diretorio)
    return {}


def verificar_vulnerabilidades_em_banners(
    banners: Iterable[str],
    base_cves=None,
    detalhado: bool = False,
) -> Tuple[List[str], List[str]]:
    """
    Verifica CVEs para uma lista de banners de serviços.

    Fluxo por banner:
    1. Extrai (produto, versão) via regex
    2. Normaliza para (vendor, product) da taxonomia NVD
    3. Consulta índice CPE

    Args:
        banners: Lista de strings no formato "porta:banner".
        base_cves: Ignorado (mantido por compatibilidade).
        detalhado: Se True, retorna (confirmadas, suspeitas) separados.

    Returns:
        Se detalhado=True: (confirmadas, suspeitas)
        Se detalhado=False: lista única sem duplicatas
    """
    all_confirmed: List[str] = []
    all_suspected: List[str] = []

    for banner_entry in banners:
        raw_banner = banner_entry.split(":", 1)[-1] if ":" in banner_entry else banner_entry

        info = extract_product_version(raw_banner)
        if not info:
            continue

        product_name, version = info
        vendor, product = normalize_product(product_name)
        confirmed, suspected = check_vulnerabilities_by_cpe(vendor, product, version)
        all_confirmed.extend(confirmed)
        all_suspected.extend(suspected)

    confirmed_unique = sorted(set(all_confirmed))
    suspected_unique = sorted(set(all_suspected))

    if detalhado:
        return confirmed_unique, suspected_unique
    return sorted(set(confirmed_unique + suspected_unique))
