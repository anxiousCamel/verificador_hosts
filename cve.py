"""
# cve.py

## Propósito
Eliminar falsos positivos trocando a busca por descrição por **CPE + faixa de versão**,
com **cache em disco** e **índice rápido**.

## O que este módulo faz
- Lê JSONs da NVD (pasta `nvd_data/`).
- Indexa por (vendor, product) guardando:
  - `anyVersion` (qualquer versão),
  - `exactVersion` (quando o CPE vem com versão **exata**),
  - `versionRules` (faixas start/end inclusive/exclusive).
- Extrai (produto, versão) de banners, normaliza para a taxonomia NVD,
  e confirma CVEs por versão.

## Requisitos
- packaging>=24.0

## API (compatível)
- carregar_base_local_cves(diretorio="nvd_data", usar_cache=True)
- verificar_vulnerabilidades_em_banners(banners, base_cves=None, detalhado=False)
"""

from __future__ import annotations

import os
import re
import json
import gzip
import pickle
from typing import Dict, List, Tuple, Iterable, Optional
from functools import lru_cache
from datetime import datetime
from packaging.version import Version, InvalidVersion

# ==============================
# Configs
# ==============================

DIRETORIO_NVD = os.environ.get("NVD_DIR", "nvd_data")
NVD_INDEX_PKL = os.environ.get("NVD_INDEX_PKL", os.path.join(DIRETORIO_NVD, "nvd_index.pkl"))
NVD_INDEX_MAX_YEARS = int(os.environ.get("NVD_INDEX_MAX_YEARS", "5"))  # anos recentes a considerar
CPE_PART_ALLOWED = os.environ.get("CPE_PART_ALLOWED", "a")  # "a","o","h" ou "" p/ todos

# ==============================
# Normalização e parsing
# ==============================

MAP_NORMALIZACAO: Dict[str, Tuple[str, str]] = {
    "openssh": ("openbsd", "openssh"),
    "apache": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "nginx": ("nginx", "nginx"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "openssl": ("openssl", "openssl"),
    "proftpd": ("proftpd_project", "proftpd"),
    "pure-ftpd": ("pureftpd", "pureftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "opensmtpd": ("openbsd", "opensmtpd"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
}

def _clean(s: str) -> str:
    return (s or "").strip().lower()

def normalizar_produto(nome: str) -> Tuple[str, str]:
    """
    ## normalizar_produto
    Converte nome de banner para (vendor, product) próximo ao da NVD.
    """
    base = _clean(nome)
    compact = base.replace("-", "").replace("_", "")
    for k, vp in MAP_NORMALIZACAO.items():
        if compact.startswith(k.replace("-", "")):
            return vp
    return (base.replace(" ", "_"), base.replace(" ", "_"))

def extrair_nome_versao_banner(banner: str) -> Optional[Tuple[str, str]]:
    """
    ## extrair_nome_versao_banner
    Extrai (produto, versão) de um banner comum:
      - "Server: Apache/2.4.49 ..."  -> ("apache","2.4.49")
      - "OpenSSH_8.2p1 ..."          -> ("openssh","8.2p1")
      - "nginx/1.24.0"               -> ("nginx","1.24.0")
    """
    if not banner:
        return None
    b = banner.strip()

    # nome/versao ou nome vX.Y.Z, aceitando sufixos distro (ex.: -1ubuntu1)
    m = re.search(r'([A-Za-z0-9\-_]+)[/\s]v?([0-9]+(?:\.[0-9a-z]+){0,3}(?:[-_][0-9a-z\.]+)?)',
                  b, flags=re.IGNORECASE)
    if m:
        return (_clean(m.group(1)), m.group(2))

    # nome_versao (ex.: OpenSSH_8.2p1)
    m = re.search(r'([A-Za-z0-9\-_]+)_([0-9]+[0-9a-zA-Z\.\-]*)', b)
    if m:
        return (_clean(m.group(1)), m.group(2))

    return None

# ==============================
# CPE e comparação de versões
# ==============================

def parse_cpe23(cpe: str) -> Optional[Dict[str, str]]:
    """
    ## parse_cpe23
    "cpe:2.3:a:vendor:product:version:update:..." -> dict mínimo.
    """
    partes = (cpe or "").split(":")
    if len(partes) < 6:
        return None
    return {
        "part": partes[2],    # a=application, o=os, h=hardware
        "vendor": partes[3],
        "product": partes[4],
        "version": partes[5],
    }

def _to_version(v: Optional[str]) -> Optional[Version]:
    """
    ## _to_version
    Converte para Version; se inválida (ex.: 8.2p1), tenta heurística numérica.
    """
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        m = re.match(r'^([0-9]+(?:\.[0-9]+){0,3})', v)
        if m:
            try:
                return Version(m.group(1))
            except InvalidVersion:
                return None
        return None

def comparar_versao(ver_alvo: str, regra: Dict[str, Optional[str]]) -> bool:
    """
    ## comparar_versao
    Compara ver_alvo com faixa (start/end, inclusive/exclusive).
    """
    va = _to_version(ver_alvo)
    if va is None:
        return False

    vsi = _to_version(regra.get("versionStartIncluding"))
    vse = _to_version(regra.get("versionStartExcluding"))
    vei = _to_version(regra.get("versionEndIncluding"))
    vee = _to_version(regra.get("versionEndExcluding"))

    if vsi and va < vsi:
        return False
    if vse and va <= vse:
        return False
    if vei and va > vei:
        return False
    if vee and va >= vee:
        return False
    return True

def versoes_iguais(v1: str, v2: str) -> bool:
    """
    ## versoes_iguais
    Compara versões tratando sufixos não semânticos (ex.: '8.2p1' ~ '8.2').
    Tenta semântico; se não der, compara literal.
    """
    a, b = _to_version(v1), _to_version(v2)
    if a is not None and b is not None:
        return a == b
    return (v1 or "").strip() == (v2 or "").strip()

# ==============================
# Cache do índice (pickle)
# ==============================

def _ano_do_arquivo(nome: str) -> Optional[int]:
    m = re.search(r'(\d{4})', nome or "")
    return int(m.group(1)) if m else None

def _carregar_indice_cache() -> Optional[Dict[Tuple[str, str], List[Dict]]]:
    try:
        if os.path.exists(NVD_INDEX_PKL):
            with open(NVD_INDEX_PKL, "rb") as f:
                return pickle.load(f)
    except Exception:
        return None
    return None

def _salvar_indice_cache(indice: Dict[Tuple[str, str], List[Dict]]) -> None:
    try:
        os.makedirs(os.path.dirname(NVD_INDEX_PKL), exist_ok=True)
        with open(NVD_INDEX_PKL, "wb") as f:
            pickle.dump(indice, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass

# ==============================
# Iteração de nós (nodes/children)
# ==============================

def _iter_cpe_matches(nodes: List[dict]):
    """Percorre `nodes` e `children` recursivamente, gerando matches de CPE."""
    if not nodes:
        return
    stack = list(nodes)
    while stack:
        node = stack.pop()
        for m in node.get("cpe_match", []) or []:
            yield m
        childs = node.get("children") or []
        if childs:
            stack.extend(childs)

# ==============================
# Construção do índice CPE
# ==============================

@lru_cache(maxsize=1)
def construir_indice_cpe(diretorio: str = DIRETORIO_NVD) -> Dict[Tuple[str, str], List[Dict]]:
    """
    ## construir_indice_cpe
    Gera: { (vendor, product): [ { 'cve', 'anyVersion', 'exactVersion'?, 'versionRules' } ...] }

    Otimizações:
    - Cache pickle (nvd_index.pkl).
    - Recorte por anos (`NVD_INDEX_MAX_YEARS`).
    - Filtro por part (default "a").
    """
    cache = _carregar_indice_cache()
    if cache:
        return cache

    indice: Dict[Tuple[str, str], List[Dict]] = {}
    if not os.path.exists(diretorio):
        _salvar_indice_cache(indice)
        return indice

    ano_atual = datetime.now().year
    limiar = ano_atual - NVD_INDEX_MAX_YEARS
    part_filter = (CPE_PART_ALLOWED or "").strip().lower()

    def _abrir(caminho: str):
        if caminho.endswith(".gz"):
            return gzip.open(caminho, "rt", encoding="utf-8")
        return open(caminho, "r", encoding="utf-8")

    for root, _, arquivos in os.walk(diretorio):
        for arquivo in arquivos:
            if not (arquivo.endswith(".json") or arquivo.endswith(".json.gz")):
                continue

            ano = _ano_do_arquivo(arquivo)
            if ano and ano < limiar:
                continue

            caminho = os.path.join(root, arquivo)
            try:
                with _abrir(caminho) as f:
                    dados = json.load(f)
            except Exception:
                continue

            itens = dados.get("CVE_Items") or dados.get("vulnerabilities")
            if not itens:
                continue

            for item in itens:
                # Layouts suportados
                if "cve" in item:
                    cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                    nodes = item.get("configurations", {}).get("nodes", [])
                else:
                    vuln = item.get("cve") or item.get("vuln") or {}
                    cve_id = (vuln.get("id")
                              or vuln.get("CVE_data_meta", {}).get("ID", "")
                              or item.get("id", ""))
                    nodes = item.get("configurations", {}).get("nodes", [])

                for match in _iter_cpe_matches(nodes):
                    if not match.get("vulnerable", False):
                        continue
                    cpe_str = match.get("cpe23Uri") or match.get("criteria") or ""
                    cpe = parse_cpe23(cpe_str)
                    if not cpe:
                        continue

                    if part_filter and cpe.get("part") != part_filter:
                        continue

                    key = (cpe["vendor"], cpe["product"])
                    regra = {
                        "versionStartIncluding": match.get("versionStartIncluding"),
                        "versionStartExcluding": match.get("versionStartExcluding"),
                        "versionEndIncluding": match.get("versionEndIncluding"),
                        "versionEndExcluding": match.get("versionEndExcluding"),
                    }
                    any_version = cpe["version"] in ("*", "-", "", None)

                    # Se vier versão exata E sem faixa -> tratar como igualdade
                    has_range = any(regra.values())
                    exact_version = None
                    if not any_version and not has_range:
                        exact_version = cpe["version"]

                    entry = {
                        "cve": cve_id,
                        "anyVersion": any_version,
                        "versionRules": regra,
                    }
                    if exact_version:
                        entry["exactVersion"] = exact_version

                    indice.setdefault(key, []).append(entry)

    _salvar_indice_cache(indice)
    return indice

# ==============================
# Verificação por (vendor, product, version)
# ==============================

def verificar_vulnerabilidades_por_cpe(vendor: str, product: str, version: Optional[str]) -> Tuple[List[str], List[str]]:
    """
    ## verificar_vulnerabilidades_por_cpe
    Retorna (confirmadas, suspeitas):
    - confirmadas: versão dentro da faixa, OU `anyVersion` com versão conhecida,
      OU `exactVersion` igual.
    - suspeitas: produto casa mas sem versão do alvo (não há como confirmar).
    """
    indice = construir_indice_cpe()
    buckets = indice.get((vendor, product), [])
    confirmadas: List[str] = []
    suspeitas: List[str] = []

    for entry in buckets:
        cve = entry["cve"]

        if entry.get("anyVersion"):
            if version:
                confirmadas.append(cve)
            else:
                suspeitas.append(cve)
            continue

        exact = entry.get("exactVersion")
        if exact is not None:
            if version and versoes_iguais(version, exact):
                confirmadas.append(cve)
            elif not version:
                suspeitas.append(cve)
            continue  # se há exact, não há faixa

        rules = entry.get("versionRules") or {}
        if version and any(rules.values()) and comparar_versao(version, rules):
            confirmadas.append(cve)
        elif not version:
            suspeitas.append(cve)

    return sorted(set(confirmadas)), sorted(set(suspeitas))

# ==============================
# API compatível com o projeto
# ==============================

def carregar_base_local_cves(diretorio: str = DIRETORIO_NVD, usar_cache: bool = True):
    """
    ## carregar_base_local_cves
    Compatibilidade: apenas garante que o índice esteja pronto (em cache).
    """
    if not usar_cache:
        construir_indice_cpe.cache_clear()
        try:
            if os.path.exists(NVD_INDEX_PKL):
                os.remove(NVD_INDEX_PKL)
        except Exception:
            pass
    _ = construir_indice_cpe(diretorio)
    return {}  # mantido por compat

def verificar_vulnerabilidades_em_banners(
    banners: Iterable[str],
    base_cves=None,            # ignorado (compat)
    detalhado: bool = False
):
    """
    ## verificar_vulnerabilidades_em_banners
    Recebe banners (ex.: "80:Server: Apache/2.4.49 ...").
    - Extrai (produto, versão).
    - Normaliza para (vendor, product).
    - Consulta índice CPE (any/exact/faixa).

    Retorna:
      - detalhado=False: lista única (confirmadas + suspeitas, sem duplicatas)
      - detalhado=True: (confirmadas, suspeitas)
    """
    confirmadas_agg: List[str] = []
    suspeitas_agg: List[str] = []

    for b in banners:
        raw = b.split(":", 1)[-1] if ":" in b else b
        info = extrair_nome_versao_banner(raw)
        if not info:
            continue
        produto, versao = info
        vendor, product = normalizar_produto(produto)
        c, s = verificar_vulnerabilidades_por_cpe(vendor, product, versao)
        confirmadas_agg.extend(c)
        suspeitas_agg.extend(s)

    confirmadas_uniq = sorted(set(confirmadas_agg))
    suspeitas_uniq = sorted(set(suspeitas_agg))

    if detalhado:
        return confirmadas_uniq, suspeitas_uniq
    return sorted(set(confirmadas_uniq + suspeitas_uniq))
