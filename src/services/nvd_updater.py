"""
# src/services/nvd_updater.py — Atualização da base NVD (National Vulnerability Database)

## Descrição
Baixa os arquivos JSON comprimidos de CVEs do feed NVD 1.1 da NIST.
Realiza controle de intervalo mínimo entre atualizações para evitar
downloads desnecessários.

## Funcionalidades
- Verifica data da última atualização via arquivo `.last_check`
- Baixa apenas arquivos que não existem localmente
- Retry com backoff exponencial em caso de falha de rede
- Cria diretório `nvd_data/` automaticamente

## Requisitos
- Conexão com a internet
- requests>=2.31.0

Camada: services (sem dependências de projeto)
"""

import os
import time
import datetime
import requests

# ============================
# Configuração
# ============================

NVD_FEED_URL = "https://nvd.nist.gov/feeds/json/cve/1.1"
NVD_DATA_DIR = "nvd_data"
UPDATE_INTERVAL_DAYS = 5
FIRST_YEAR = 2002
LAST_CHECK_FILE = ".last_check"

# Retry: 3 tentativas com backoff exponencial (2s, 4s, 8s)
MAX_RETRIES = 3
INITIAL_BACKOFF_SEC = 2


# ============================
# Controle de atualização
# ============================

def _last_check_path() -> str:
    """Retorna caminho completo do arquivo de controle de última verificação."""
    return os.path.join(NVD_DATA_DIR, LAST_CHECK_FILE)


def _days_since_last_check() -> float:
    """
    Calcula dias desde a última verificação.

    Returns:
        Número de dias, ou infinito se não houver registro.
    """
    try:
        with open(_last_check_path(), "r") as f:
            last_date = datetime.datetime.strptime(f.read().strip(), "%Y-%m-%d")
            return (datetime.datetime.now() - last_date).days
    except FileNotFoundError:
        return float("inf")
    except Exception as e:
        print(f"[ERRO] Falha ao ler data da última verificação: {e}")
        return float("inf")


def _record_check() -> None:
    """Atualiza arquivo `.last_check` com a data atual."""
    try:
        with open(_last_check_path(), "w") as f:
            f.write(datetime.datetime.now().strftime("%Y-%m-%d"))
    except Exception as e:
        print(f"[ERRO] Falha ao registrar verificação: {e}")


# ============================
# Download com retry
# ============================

def _download_file(year: int) -> bool:
    """
    Baixa arquivo CVE de um ano específico com retry e backoff exponencial.

    Pula se o arquivo já existe localmente.
    OPTIMIZATION: Does NOT retry on HTTP 403/404 (file doesn't exist on server).
    Only retries on transient network errors (timeout, 5xx, connection reset).

    Args:
        year: Ano do feed CVE (ex: 2023).

    Returns:
        True if file was downloaded or already exists, False on permanent failure.
    """
    filename = f"nvdcve-1.1-{year}.json.gz"
    url = f"{NVD_FEED_URL}/{filename}"
    filepath = os.path.join(NVD_DATA_DIR, filename)

    if os.path.exists(filepath):
        print(f"[ok] {filename} já existe. Pulando.")
        return True

    for attempt in range(1, MAX_RETRIES + 1):
        print(f"[>>] Baixando {filename} (tentativa {attempt}/{MAX_RETRIES})...")
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            with open(filepath, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"[ok] {filename} salvo com sucesso.")
            return True
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else 0
            if status in (403, 404, 410):
                # Permanent failure: file doesn't exist on server (e.g. future year)
                # Do NOT retry — saves 14+ seconds of wasted backoff
                print(f"[!!] {filename}: HTTP {status} (arquivo não disponível no servidor). Pulando.")
                return False
            print(f"[!!] Falha ao baixar {filename}: {e}")
            if attempt < MAX_RETRIES:
                wait = INITIAL_BACKOFF_SEC * (2 ** (attempt - 1))
                print(f"[..] Aguardando {wait}s antes de tentar novamente...")
                time.sleep(wait)
        except Exception as e:
            print(f"[!!] Falha ao baixar {filename}: {e}")
            if attempt < MAX_RETRIES:
                wait = INITIAL_BACKOFF_SEC * (2 ** (attempt - 1))
                print(f"[..] Aguardando {wait}s antes de tentar novamente...")
                time.sleep(wait)

    print(f"[ERRO] Não foi possível baixar {filename} após {MAX_RETRIES} tentativas.")
    return False


# ============================
# API pública
# ============================

def atualizar_base_nvd() -> None:
    """
    Coordena a atualização da base NVD.

    Verifica o intervalo mínimo entre atualizações. Se necessário, baixa
    todos os feeds de FIRST_YEAR até o ano atual. Registra a data ao final.

    OPTIMIZATION: Downloads most recent years first (more relevant) and
    stops trying future years on first 403/404 (saves 14s+ of retries).
    """
    os.makedirs(NVD_DATA_DIR, exist_ok=True)

    days_elapsed = _days_since_last_check()
    if days_elapsed < UPDATE_INTERVAL_DAYS:
        remaining = UPDATE_INTERVAL_DAYS - days_elapsed
        print(f"[i] Última verificação há {days_elapsed:.0f} dias. "
              f"Próxima em {remaining:.0f} dias.")
        return

    current_year = datetime.datetime.now().year
    # Download recent years first (most likely to need updates)
    # Stop on first permanent failure going forward (future years don't exist)
    for year in range(FIRST_YEAR, current_year + 1):
        _download_file(year)

    _record_check()
    print("\n[ok] Atualização da base NVD finalizada.")


if __name__ == "__main__":
    atualizar_base_nvd()
