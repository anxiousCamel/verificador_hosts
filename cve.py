"""
# cve.py

## Descrição
Este módulo realiza a verificação de vulnerabilidades conhecidas (CVEs) com base nos banners encontrados durante
o escaneamento de portas. Ele utiliza arquivos locais da NVD (`.json` ou `.json.gz`) para consultar possíveis falhas
e permite cache em formato `pickle` para acelerar carregamentos futuros.

## Funcionalidades
- Leitura local da base NVD em JSON ou GZ
- Extração de nome/versão via regex dos banners
- Verificação por correspondência textual em CVEs
- Geração de cache para otimizar desempenho
- Spinner visual de carregamento

## Requisitos
- Diretório `nvd_data` com arquivos `nvdcve-1.1-*.json(.gz)`
- Python 3.6+
- Bibliotecas: os, json, gzip, re, threading, itertools, time, pickle

## Autor
Luiz
"""

import os
import json
import gzip
import pickle
import re
import threading
import itertools
import time

# Caminho padrão do diretório com os arquivos CVE da NVD
DIRETORIO_NVD = "nvd_data"
ARQUIVO_CACHE = "base_cves_cache.pkl"


def _spinner(label="Lendo arquivos da NVD"):
    """
    Exibe um spinner no terminal para indicar carregamento em progresso.

    Parâmetros:
        label (str): Mensagem que será mostrada junto ao spinner.

    Retorna:
        threading.Event: Objeto de controle para encerrar o spinner.
    """
    done = threading.Event()

    def animate():
        for c in itertools.cycle(['|', '/', '—', '\\']):
            if done.is_set():
                break
            print(f"\r{label} {c} ", end='', flush=True)
            time.sleep(0.1)
        print("\r" + " " * (len(label) + 4), end="\r")  # limpa linha

    t = threading.Thread(target=animate)
    t.start()
    return done


def carregar_base_local_cves(diretorio=DIRETORIO_NVD, usar_cache=True):
    """
    Carrega os CVEs da base local da NVD (json/gz), com suporte a cache.

    Parâmetros:
        diretorio (str): Caminho do diretório com os arquivos da NVD.
        usar_cache (bool): Se True, tenta carregar de um cache `.pkl`.

    Retorna:
        dict: Mapeamento {cve_id: descricao}.
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

    # Inicia spinner de carregamento
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
        spinner_done.set()

    # Salva cache local
    try:
        with open(ARQUIVO_CACHE, "wb") as f:
            pickle.dump(base_cves, f)
    except Exception as e:
        print(f"[Erro] ao salvar cache: {e}")

    return base_cves


def verificar_vulnerabilidades_em_banners(banners, base_cves=None):
    """
    Verifica possíveis CVEs com base nos banners identificados.

    Parâmetros:
        banners (list[str]): Lista de strings com banners coletados.
        base_cves (dict): Mapeamento {cve_id: descricao} da NVD local.

    Retorna:
        list[str]: Lista de CVEs correspondentes aos banners.
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
    Extrai nome e versão do software a partir de uma string de banner.

    Exemplo:
        'Apache/2.4.49' → 'apache 2.4.49'

    Parâmetros:
        banner (str): Banner bruto do serviço.

    Retorna:
        str | None: Nome e versão extraídos ou None se não for possível.
    """
    match = re.search(r'([a-zA-Z\-_]+)[/\s]?([0-9]+\.[0-9]+(?:\.[0-9]+)?)', banner)
    if match:
        nome = match.group(1).lower()
        versao = match.group(2)
        return f"{nome} {versao}"
    return None
