"""
# Script: atualizar_nvd.py

## Descrição:
Atualiza automaticamente os arquivos CVE da NVD (National Vulnerability Database)
com base na última verificação. Baixa apenas os anos faltantes ou se ultrapassado
o número definido de dias desde a última atualização.

## Requisitos:
- Internet ativa
- Python 3.6+
- requests

## Autor:
Luiz
"""

import os
import datetime
import requests

# ======= CONFIGURAÇÃO =======
URL_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
DIRETORIO = "nvd_data"
DIAS_ENTRE_ATUALIZACOES = 5
ANO_INICIAL = 2002
ARQUIVO_LAST_CHECK = ".last_check"
# ============================


def get_ano_atual():
    return datetime.datetime.now().year


def caminho_last_check():
    return os.path.join(DIRETORIO, ARQUIVO_LAST_CHECK)


def dias_desde_ultima_verificacao():
    """
    Retorna o número de dias desde a última verificação registrada.
    Se não houver registro, força atualização.
    """
    try:
        with open(caminho_last_check(), "r") as f:
            ultima = datetime.datetime.strptime(f.read().strip(), "%Y-%m-%d")
            hoje = datetime.datetime.now()
            return (hoje - ultima).days
    except FileNotFoundError:
        return float("inf")
    except Exception as e:
        print(f"[ERRO] Falha ao ler data da última verificação: {e}")
        return float("inf")


def registrar_verificacao():
    """
    Registra a data da última verificação no arquivo de controle.
    """
    try:
        with open(caminho_last_check(), "w") as f:
            f.write(datetime.datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        print(f"[ERRO] Falha ao registrar última verificação: {e}")


def baixar_arquivo(ano: int):
    """
    Baixa o arquivo do ano especificado, se ainda não estiver presente.
    """
    nome_arquivo = f"nvdcve-1.1-{ano}.json.gz"
    url = f"{URL_BASE}/{nome_arquivo}"
    caminho = os.path.join(DIRETORIO, nome_arquivo)

    if os.path.exists(caminho):
        print(f"[✓] {nome_arquivo} já existe. Pulando.")
        return

    print(f"[↓] Baixando {nome_arquivo}...")
    try:
        r = requests.get(url, stream=True, timeout=30)
        r.raise_for_status()
        with open(caminho, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[✔] {nome_arquivo} salvo com sucesso.")
    except Exception as e:
        print(f"[ERRO] Falha ao baixar {nome_arquivo}: {e}")


def atualizar_base_nvd():
    """
    Atualiza a base de dados da NVD.
    Verifica o intervalo desde a última execução e realiza download apenas se necessário.
    """
    os.makedirs(DIRETORIO, exist_ok=True)

    dias_passados = dias_desde_ultima_verificacao()
    if dias_passados < DIAS_ENTRE_ATUALIZACOES:
        print(f"[i] Última verificação foi há {dias_passados} dias.")
        print(f"[→] Nenhuma atualização necessária. Aguarde mais {DIAS_ENTRE_ATUALIZACOES - dias_passados} dias.")
        return

    ano_atual = get_ano_atual()
    for ano in range(ANO_INICIAL, ano_atual + 1):
        baixar_arquivo(ano)

    registrar_verificacao()
    print("\n[✓] Atualização da base NVD finalizada.")


if __name__ == "__main__":
    atualizar_base_nvd()
