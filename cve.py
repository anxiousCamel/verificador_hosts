"""
# cve.py

## Descrição
Este módulo faz a verificação de vulnerabilidades conhecidas com base nos banners encontrados nas portas abertas.
Requer que os arquivos de dados da NVD estejam baixados localmente em um diretório.

## Autor
Luiz

## Dependências
- os
- json
- gzip
- re
"""

import os
import json
import gzip
import pickle
import re
import threading
import itertools
import time


# Caminho padrão do diretório com os arquivos JSON.GZ da NVD
DIRETORIO_NVD = "nvd_data"
ARQUIVO_CACHE = "base_cves_cache.pkl"

def _spinner(label="Lendo arquivos da NVD"):
    """
    Exibe um spinner giratório (|/—\) enquanto os arquivos são carregados.
    """
    done = threading.Event()

    def animate():
        for c in itertools.cycle(['|', '/', '—', '\\']):
            if done.is_set():
                break
            print(f"\r{label} {c} ", end='', flush=True)
            time.sleep(0.1)
        print("\r" + " " * (len(label) + 4), end="\r")

    t = threading.Thread(target=animate)
    t.start()
    return done



def carregar_base_local_cves(diretorio=DIRETORIO_NVD, usar_cache=True):
    """
    Carrega CVEs da base NVD, com suporte a cache via pickle.
    Mostra spinner de progresso durante carregamento dos arquivos.
    """
    if usar_cache and os.path.exists(ARQUIVO_CACHE):
        try:
            with open(ARQUIVO_CACHE, "rb") as f:
                return pickle.load(f)
        except Exception as e:
            print(f"[Erro] ao carregar cache: {e}")

    base_cves = {}
    if not os.path.exists(diretorio):
        return base_cves

    # Inicia o spinner visual
    spinner_done = _spinner("Lendo arquivos da NVD")

    try:
        for root, _, arquivos in os.walk(diretorio):
            for arquivo in arquivos:
                if not (arquivo.endswith(".json") or arquivo.endswith(".json.gz")):
                    continue

                caminho_arquivo = os.path.join(root, arquivo)
                try:
                    if arquivo.endswith(".gz"):
                        with gzip.open(caminho_arquivo, "rt", encoding="utf-8") as f:
                            dados = json.load(f)
                    else:
                        with open(caminho_arquivo, "r", encoding="utf-8") as f:
                            dados = json.load(f)

                    for item in dados.get("CVE_Items", []):
                        cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
                        descricoes = item.get("cve", {}).get("description", {}).get("description_data", [])
                        if descricoes:
                            descricao = descricoes[0].get("value", "")
                            base_cves[cve_id] = descricao
                except Exception as e:
                    print(f"[Erro] ao ler {caminho_arquivo}: {e}")
    finally:
        spinner_done.set()  # Finaliza o spinner

    # salva cache
    try:
        with open(ARQUIVO_CACHE, "wb") as f:
            pickle.dump(base_cves, f)
    except Exception as e:
        print(f"[Erro] ao salvar cache: {e}")

    return base_cves

def verificar_vulnerabilidades_em_banners(banners, base_cves=None):
    """
    Verifica vulnerabilidades conhecidas com base em banners e CVEs locais.
    Usa correspondência por nome e versão de software (extraído via regex).
    """
    vulnerabilidades = set()

    if not base_cves:
        return []

    for banner in banners:
        info_extraida = extrair_nome_versao_banner(banner)
        if not info_extraida:
            continue

        for cve_id, descricao in base_cves.items():
            if info_extraida in descricao.lower():
                vulnerabilidades.add(cve_id)

    return sorted(list(vulnerabilidades))


def extrair_nome_versao_banner(banner: str):
    """
    Extrai nome e versão do software a partir do banner.
    Ex: 'Apache/2.4.49' => 'apache 2.4.49'
    """
    match = re.search(r'([a-zA-Z\-_]+)[/\s]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', banner)
    if match:
        nome = match.group(1).lower()
        versao = match.group(2)
        return f"{nome} {versao}"
    return None

