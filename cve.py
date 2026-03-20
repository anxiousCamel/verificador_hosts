"""
# cve.py — Verificação de vulnerabilidades via CPE + faixa de versão

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

## Autor
Luiz
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

# Usa orjson se disponível (2-5x mais rápido para parsing de JSONs grandes)
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

# Mapeia nomes comuns de banners para (vendor, product) da taxonomia NVD
_PRODUCT_ALIASES: Dict[str, Tuple[str, str]] = {
    "openssh":    ("openbsd", "openssh"),
    "apache":     ("apache", "http_server"),
    "httpd":      ("apache", "http_server"),
    "nginx":      ("nginx", "nginx"),
    "lighttpd":   ("lighttpd", "lighttpd"),
    "mysql":      ("oracle", "mysql"),
    "mariadb":    ("mariadb", "mariadb"),
    "postgresql":  ("postgresql", "postgresql"),
    "openssl":    ("openssl", "openssl"),
    "proftpd":    ("proftpd_project", "proftpd"),
    "pureftpd":   ("pureftpd", "pureftpd"),
    "vsftpd":     ("vsftpd", "vsftpd"),
    "opensmtpd":  ("openbsd", "opensmtpd"),
    "postfix":    ("postfix", "postfix"),
    "dovecot":    ("dovecot", "dovecot"),
}


def normalize_product(name: str) -> Tuple[str, str]:
    """
    Converte nome de banner para (vendor, product) conforme taxonomia NVD.

    Primeiro tenta match por alias conhecido, depois usa o nome como
    vendor e product (fallback genérico).

    Args:
        name: Nome do produto extraído do banner (ex: "apache", "openssh").

    Returns:
        Tupla (vendor, product) normalizada.
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
    Extrai (produto, versão) de um banner de serviço.

    Padrões reconhecidos:
    - "Server: Apache/2.4.49 ..." → ("apache", "2.4.49")
    - "OpenSSH_8.2p1 ..."        → ("openssh", "8.2p1")
    - "nginx/1.24.0"             → ("nginx", "1.24.0")
    - "produto v1.2.3"           → ("produto", "1.2.3")

    Args:
        banner: String do banner.

    Returns:
        Tupla (produto, versão) ou None se não reconhecido.
    """
    if not banner:
        return None

    text = banner.strip()

    # Padrão: nome/versão ou nome vX.Y.Z (com sufixos distro como -1ubuntu1)
    match = re.search(
        r'([A-Za-z0-9\-_]+)[/\s]v?([0-9]+(?:\.[0-9a-z]+){0,3}(?:[-_][0-9a-z\.]+)?)',
        text, flags=re.IGNORECASE,
    )
    if match:
        return (match.group(1).strip().lower(), match.group(2))

    # Padrão: nome_versão (ex: OpenSSH_8.2p1)
    match = re.search(r'([A-Za-z0-9\-_]+)_([0-9]+[0-9a-zA-Z\.\-]*)', text)
    if match:
        return (match.group(1).strip().lower(), match.group(2))

    return None


# ==============================
# CPE e comparação de versões
# ==============================

def parse_cpe23(cpe_uri: str) -> Optional[Dict[str, str]]:
    """
    Faz parsing de uma URI CPE 2.3 para seus componentes.

    Formato: "cpe:2.3:part:vendor:product:version:update:..."

    Args:
        cpe_uri: String CPE 2.3 completa.

    Returns:
        Dict com part, vendor, product, version; ou None se inválido.
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

    Args:
        version_str: String de versão.

    Returns:
        Version ou None se impossível converter.
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
    - versionStartIncluding: target >= start
    - versionStartExcluding: target > start
    - versionEndIncluding: target <= end
    - versionEndExcluding: target < end

    Args:
        target: Versão do alvo (extraída do banner).
        rules: Dicionário com as regras de faixa da NVD.

    Returns:
        True se a versão está dentro da faixa.
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
    """
    Compara duas versões com tolerância a sufixos não-semânticos.

    Tenta comparação semver primeiro; se falhar, compara literalmente.

    Args:
        v1: Primeira versão.
        v2: Segunda versão.

    Returns:
        True se as versões são equivalentes.
    """
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

    A estrutura NVD usa nodes com children recursivos. Esta função
    usa stack iterativo (sem recursão) para evitar stack overflow
    em CVEs com árvores profundas.

    Args:
        nodes: Lista de nós de configuração do CVE.

    Yields:
        Dicionários de CPE match (com cpe23Uri, vulnerable, version ranges).
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
    """Extrai ano de um nome de arquivo NVD (ex: 'nvdcve-1.1-2023.json.gz' → 2023)."""
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

    Args:
        item: Item do JSON NVD.

    Returns:
        Tupla (cve_id, nodes).
    """
    if "cve" in item and "CVE_data_meta" in item.get("cve", {}):
        # Formato NVD 1.1
        cve_id = item["cve"]["CVE_data_meta"].get("ID", "")
        nodes = item.get("configurations", {}).get("nodes", [])
    else:
        # Formato NVD 2.0
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

    O índice permite lookup O(1) por (vendor, product) e depois iteração
    linear apenas pelos CVEs daquele produto.

    Otimizações:
    - Cache pickle em disco (evita re-parsing dos JSONs a cada execução)
    - Filtro por anos recentes (NVD_INDEX_MAX_YEARS)
    - Filtro por tipo de CPE (CPE_PART_ALLOWED)
    - Usa orjson quando disponível

    Args:
        nvd_dir: Diretório contendo os arquivos JSON/JSON.GZ da NVD.

    Returns:
        Índice CPE indexado por (vendor, product).
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

                    # Versão exata sem faixa → match por igualdade
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
    - **Confirmadas**: Versão está dentro da faixa, ou é match exato,
      ou CVE afeta todas as versões e temos versão conhecida.
    - **Suspeitas**: Produto casa mas não temos versão para confirmar.

    Args:
        vendor: Vendor NVD (ex: "apache", "openbsd").
        product: Product NVD (ex: "http_server", "openssh").
        version: Versão detectada (pode ser None).

    Returns:
        Tupla (confirmadas, suspeitas) — listas de CVE IDs.
    """
    index = build_cpe_index()
    entries = index.get((vendor, product), [])

    confirmed: List[str] = []
    suspected: List[str] = []

    for entry in entries:
        cve_id = entry["cve"]

        # CVE afeta todas as versões
        if entry.get("anyVersion"):
            if version:
                confirmed.append(cve_id)
            else:
                suspected.append(cve_id)
            continue

        # Match por versão exata
        exact = entry.get("exactVersion")
        if exact is not None:
            if version and versions_equal(version, exact):
                confirmed.append(cve_id)
            elif not version:
                suspected.append(cve_id)
            continue

        # Match por faixa de versão
        rules = entry.get("versionRules") or {}
        if version and any(rules.values()) and version_in_range(version, rules):
            confirmed.append(cve_id)
        elif not version:
            suspected.append(cve_id)

    return sorted(set(confirmed)), sorted(set(suspected))


# ==============================
# API pública (compatível com o projeto)
# ==============================

def carregar_base_local_cves(diretorio: str = NVD_DIR, usar_cache: bool = True):
    """
    Garante que o índice CPE está carregado.

    Mantida por compatibilidade. Se usar_cache=False, força rebuild do índice.

    Args:
        diretorio: Diretório dos JSONs NVD.
        usar_cache: Se False, limpa caches e reconstrói.

    Returns:
        Dict vazio (mantido por compatibilidade).
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
        banners: Lista de strings no formato "porta:banner" (ex: "80:Server: Apache/2.4.49").
        base_cves: Ignorado (mantido por compatibilidade).
        detalhado: Se True, retorna (confirmadas, suspeitas) separados.

    Returns:
        Se detalhado=True: (confirmadas, suspeitas)
        Se detalhado=False: lista única sem duplicatas
    """
    all_confirmed: List[str] = []
    all_suspected: List[str] = []

    for banner_entry in banners:
        # Remove prefixo de porta ("80:Server: ..." → "Server: ...")
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
