"""
# atualizar_nvd.py

## Descrição
Este script atualiza automaticamente a base de dados de vulnerabilidades da NVD (National Vulnerability Database),
baixando os arquivos `nvdcve-1.1-<ano>.json.gz` diretamente do site oficial da NIST.

Ele evita downloads desnecessários, realizando a verificação de atualização apenas se o último acesso tiver
ocorrido há mais de `DIAS_ENTRE_ATUALIZACOES` dias.

## Funcionalidades
- Verifica a data da última atualização da base
- Baixa automaticamente os arquivos de anos faltantes
- Garante que os arquivos mais recentes estejam salvos localmente
- Cria o diretório `nvd_data` se não existir

## Requisitos
- Conexão com a internet
- Python 3.6 ou superior
- requests

## Autor
Luiz
"""

import os
import datetime
import requests

# ========== CONFIGURAÇÃO ========== #
URL_BASE = "https://nvd.nist.gov/feeds/json/cve/1.1"
DIRETORIO = "nvd_data"
DIAS_ENTRE_ATUALIZACOES = 5
ANO_INICIAL = 2002
ARQUIVO_LAST_CHECK = ".last_check"
# ================================== #


def get_ano_atual():
    """
    Obtém o ano atual com base na data do sistema.

    Retorna:
        int: Ano atual.
    """
    return datetime.datetime.now().year


def caminho_last_check():
    """
    Retorna o caminho absoluto do arquivo de controle `.last_check`.

    Retorna:
        str: Caminho completo.
    """
    return os.path.join(DIRETORIO, ARQUIVO_LAST_CHECK)


def dias_desde_ultima_verificacao():
    """
    Calcula o número de dias desde a última verificação.

    Retorna:
        float: Número de dias passados. Retorna infinito se não houver registro ou erro de leitura.
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
    Atualiza o arquivo `.last_check` com a data atual.
    """
    try:
        with open(caminho_last_check(), "w") as f:
            f.write(datetime.datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        print(f"[ERRO] Falha ao registrar última verificação: {e}")


def baixar_arquivo(ano: int):
    """
    Realiza o download do arquivo CVE para o ano especificado.

    Parâmetros:
        ano (int): Ano desejado da base CVE.

    Ação:
        - Se o arquivo já existir localmente, ele será ignorado.
        - Caso contrário, será baixado da NVD.
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
    Função principal que coordena a atualização da base NVD.

    - Verifica se o intervalo mínimo entre atualizações foi respeitado.
    - Caso necessário, realiza o download de todos os arquivos desde 2002 até o ano atual.
    - Registra a nova data de atualização ao final.
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
