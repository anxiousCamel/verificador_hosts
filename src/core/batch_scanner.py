"""
# src/core/batch_scanner.py — Orquestração de varredura em lotes

## Descrição
Coordena a varredura paralela de hosts com governança adaptativa e cache.
Não faz I/O com usuário — essa responsabilidade é de cli/scanner_cli.py.

## Fluxo de run_batch_scan()
1. Separa IPs cacheados dos que precisam ser varridos
2. Varre em lotes com ThreadPoolExecutor
3. Após cada lote: salva cache e consulta AdaptiveGovernor
4. Governança adapta batch_size, host_workers, port_workers, timeout em runtime

## Nota sobre import tardio de scan_service
scan_service lê VH_MAX_SOCKETS e VH_RESOLVE_HOSTNAME no momento do import.
Por isso scan_service é importado DENTRO de run_batch_scan(), após o chamador
ter configurado os ENV vars via config.

Camada: core
Dependências: src.core.governor, src.infra.cache, src.services.cve_analyzer
"""

from __future__ import annotations

import os
import sys
import time
import threading
import itertools
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

from tqdm import tqdm
from rich.console import Console

from src.core.governor import AdaptiveGovernor
from src.infra.cache import ScanCache

console = Console()

NVD_DIR = "nvd_data"
NVD_LAST_UPDATE_FILE = os.path.join(NVD_DIR, "ultima_atualizacao.txt")
NVD_UPDATE_INTERVAL_DAYS = 7


# ==============================
# Controle de atualização NVD
# ==============================

def needs_nvd_update() -> bool:
    """
    Verifica se a base NVD precisa ser atualizada.

    Returns:
        True se o arquivo de controle não existe ou se a última
        atualização foi há mais de NVD_UPDATE_INTERVAL_DAYS dias.
    """
    try:
        if not os.path.exists(NVD_LAST_UPDATE_FILE):
            return True
        with open(NVD_LAST_UPDATE_FILE, "r", encoding="utf-8") as f:
            last_date = datetime.strptime(f.read().strip(), "%Y-%m-%d")
        return datetime.now() - last_date > timedelta(days=NVD_UPDATE_INTERVAL_DAYS)
    except Exception:
        return True


def record_nvd_update() -> None:
    """Registra a data da última atualização da base NVD."""
    os.makedirs(NVD_DIR, exist_ok=True)
    with open(NVD_LAST_UPDATE_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.now().strftime("%Y-%m-%d"))


# ==============================
# Spinner de atividade
# ==============================

def start_spinner(message: str = "Processando...") -> threading.Event:
    """
    Inicia um spinner leve em thread daemon.

    Args:
        message: Texto exibido junto ao spinner.

    Returns:
        threading.Event para sinalizar parada (chame stop_event.set()).
    """
    stop_event = threading.Event()
    chars = itertools.cycle(["|", "/", "-", "\\"])

    def _spin():
        while not stop_event.is_set():
            sys.stdout.write(f"\r{message} {next(chars)}")
            sys.stdout.flush()
            time.sleep(0.1)
        sys.stdout.write("\r" + " " * (len(message) + 4) + "\r")
        sys.stdout.flush()

    threading.Thread(target=_spin, daemon=True).start()
    return stop_event


# ==============================
# Verificação de CVEs (centralizada)
# ==============================

def run_cve_checks(hosts: Dict[str, dict]) -> None:
    """
    Verifica CVEs para todos os hosts com banners, em uma única passada.

    Centralizar aqui evita CVEs duplicados (antes eram verificados
    em scan_service e batch_scanner ao mesmo tempo).

    Args:
        hosts: Dicionário IP -> resultado do scan. Modificado in-place.
    """
    hosts_with_banners = {
        ip: data for ip, data in hosts.items()
        if data.get("banners")
    }

    if not hosts_with_banners:
        console.print("[yellow]Nenhum banner coletado; pulando verificação de CVEs.[/yellow]")
        return

    console.print("\n[bold cyan]Calculando CVEs (CPE + faixa de versão)...[/bold cyan]")
    try:
        from src.services.cve_analyzer import (
            carregar_base_local_cves,
            verificar_vulnerabilidades_em_banners,
        )

        carregar_base_local_cves()

        for ip, data in hosts_with_banners.items():
            confirmed, suspected = verificar_vulnerabilidades_em_banners(
                data["banners"], detalhado=True
            )
            data["vulnerabilidades"] = [
                *confirmed,
                *[f"{cve} (suspeita)" for cve in suspected],
            ]
    except Exception as e:
        console.print(f"[red]Falha ao calcular CVEs: {e}[/red]")


# ==============================
# Varredura em lotes
# ==============================

def run_batch_scan(
    config: dict,
    ip_list: List[str],
    oui_table: dict,
) -> Dict[str, dict]:
    """
    Executa varredura em lotes com governança adaptativa e cache.

    Nota: importa scan_service internamente pois ele lê ENV vars no import.
    O chamador (scanner_cli.py) deve configurar VH_MAX_SOCKETS,
    VH_RESOLVE_HOSTNAME e VH_TCP_ONLY antes de chamar esta função.

    Args:
        config: Dicionário retornado por auto_configurar().
        ip_list: Lista de IPs a varrer.
        oui_table: Tabela OUI de fabricantes.

    Returns:
        Dicionário IP -> resultado do scan.
    """
    # Import tardio: scan_service lê ENV vars no módulo-nível
    from src.services.scan_service import scan_host

    batch_size = max(1, int(config["batch_size"]))
    adaptive = bool(config.get("adaptive", True))

    host_workers = int(config["max_workers_hosts"])
    port_workers = int(config["max_workers_portas"])
    socket_timeout = float(config["timeout_socket"])

    results: Dict[str, dict] = {}
    scan_cache = ScanCache()
    spinner = start_spinner("Verificando hosts e portas")

    governor = AdaptiveGovernor(
        batch_size=batch_size,
        host_workers=host_workers,
        port_workers=port_workers,
        socket_timeout=socket_timeout,
        slow_threshold_sec=max(40.0, socket_timeout * 8),
        very_slow_threshold_sec=max(60.0, socket_timeout * 12),
        fast_threshold_sec=max(12.0, socket_timeout * 3),
    )

    # Separar IPs cacheados dos que precisam ser varridos
    ips_to_scan = []
    cache_hits = 0
    for ip in ip_list:
        cached = scan_cache.get(ip)
        if cached:
            results[ip] = cached
            cache_hits += 1
        else:
            ips_to_scan.append(ip)

    if cache_hits > 0:
        console.print(
            f"[bold green]Cache:[/bold green] {cache_hits} hosts recuperados do cache, "
            f"{len(ips_to_scan)} a varrer"
        )

    total_to_scan = len(ips_to_scan)
    total_ips = len(ip_list)
    progress_total = tqdm(
        total=total_ips, initial=cache_hits,
        desc="Total", ncols=100, position=0, dynamic_ncols=True,
    )

    try:
        pos = 0
        batch_idx = 0

        while pos < total_to_scan:
            batch_idx += 1
            batch_end = min(total_to_scan, pos + batch_size)
            batch_ips = ips_to_scan[pos:batch_end]
            pos = batch_end

            t0 = time.time()

            progress_batch = tqdm(
                total=len(batch_ips),
                desc=f"Lote {batch_idx} (hosts={host_workers},portas={port_workers},batch={batch_size})",
                ncols=100, position=1, leave=False, dynamic_ncols=True,
            )

            with ThreadPoolExecutor(max_workers=host_workers) as executor:
                futures = {
                    executor.submit(scan_host, ip, oui_table, port_workers, socket_timeout): ip
                    for ip in batch_ips
                }
                timeouts = 0
                completed = 0

                for future in as_completed(futures):
                    ip = futures[future]
                    try:
                        result = future.result(timeout=(socket_timeout * 2) + 5)
                    except Exception as exc:
                        timeouts += 1
                        result = {
                            "ip": ip, "status": "OFFLINE", "nome": "N/D",
                            "mac": "N/D", "fabricante": "N/D", "so": "N/D",
                            "portas": [], "banners": [], "vulnerabilidades": [],
                            "latencia": -1.0, "erro": str(exc),
                        }
                    results[result["ip"]] = result
                    scan_cache.put(result["ip"], result)
                    completed += 1
                    progress_batch.update(1)
                    progress_total.update(1)

            progress_batch.close()
            scan_cache.save()  # Resiliência a crashes

            duration = time.time() - t0

            if adaptive:
                adjusted, msg = governor.suggest(
                    batch_duration=duration,
                    timeouts=timeouts,
                    completed=completed,
                )
                if adjusted:
                    batch_size = governor.batch
                    host_workers = governor.hosts
                    port_workers = governor.ports
                    socket_timeout = governor.timeout
                    console.print(f"[yellow]Adaptando: {msg}[/yellow]")

    finally:
        spinner.set()
        scan_cache.save()
        try:
            progress_total.close()
        except Exception:
            pass

    return results
