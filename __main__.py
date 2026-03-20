"""
# __main__.py — Orquestrador principal do Verificador de Hosts

## Descrição
Ponto de entrada do sistema de auditoria de rede. Coordena:
1. Auto-configuração (presets, ENV, modo interativo)
2. Atualização opcional da base NVD
3. Carregamento da tabela OUI (fabricantes)
4. Varredura paralela de hosts em lotes (batches)
5. Governança adaptativa (ajusta paralelismo conforme performance da rede)
6. Verificação de CVEs nos banners coletados (única passada, centralizada)
7. Relatório visual no terminal e exportação CSV

## Governança Adaptativa
O `AdaptiveGovernor` monitora a duração e taxa de timeouts de cada lote:
- **Reduz** batch/hosts/portas quando a rede está lenta ou saturada
- **Aumenta** gradualmente após lotes bons consecutivos
- Usa cooldown para evitar oscilação (efeito "sanfona")

## Autor
Luiz
"""

from __future__ import annotations

import os
import sys
import time
import threading
import itertools
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Tuple

from tqdm import tqdm
from rich.console import Console

from config import auto_configurar
from utils import solicitar_dados_input, carregar_tabela_oui
from relatorio import gerar_tabela, exportar_csv
from atualizar_nvd import atualizar_base_nvd

# ==============================
# Constantes
# ==============================

NVD_DIR = "nvd_data"
NVD_LAST_UPDATE_FILE = os.path.join(NVD_DIR, "ultima_atualizacao.txt")
NVD_UPDATE_INTERVAL_DAYS = 7

console = Console()


# ==============================
# Controle de atualização NVD
# ==============================

def _needs_nvd_update() -> bool:
    """
    Verifica se a base NVD precisa ser atualizada.

    Retorna True se o arquivo de controle não existe ou se a última
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


def _record_nvd_update() -> None:
    """Registra a data da última atualização da base NVD."""
    os.makedirs(NVD_DIR, exist_ok=True)
    with open(NVD_LAST_UPDATE_FILE, "w", encoding="utf-8") as f:
        f.write(datetime.now().strftime("%Y-%m-%d"))


# ==============================
# Spinner de atividade
# ==============================

def _start_spinner(message: str = "Processando...") -> threading.Event:
    """
    Inicia um spinner leve em thread daemon.

    Args:
        message: Texto exibido junto ao spinner.

    Returns:
        threading.Event para sinalizar parada.
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
# Governança adaptativa
# ==============================

class AdaptiveGovernor:
    """
    Ajusta dinamicamente os parâmetros de varredura com base na performance.

    Estratégia conservadora com histerese:
    - Reduz batch primeiro (menos disruptivo), depois hosts, depois portas
    - Só aumenta após N lotes bons consecutivos
    - Cooldown entre ajustes evita oscilação

    Critérios de redução:
    - Lote muito lento (>60s): reduz batch em 15%
    - Lento + timeouts >10%: reduz batch em 15%
    - 2+ lotes lentos seguidos: reduz hosts em 15%
    - 3+ lotes lentos seguidos: reduz portas em 1

    Critérios de aumento:
    - 3 lotes bons consecutivos (<12s, <5% timeouts): +1 batch/hosts/portas

    Args:
        batch_size: Tamanho inicial do lote.
        host_workers: Workers de host iniciais.
        port_workers: Workers de porta iniciais.
        socket_timeout: Timeout inicial.
        limits: Dicionário com limites min/max (opcional).
        thresholds: Dicionário com limiares de decisão (opcional).
    """

    def __init__(
        self,
        batch_size: int,
        host_workers: int,
        port_workers: int,
        socket_timeout: float,
        *,
        # Limites
        batch_min: int = 6, batch_max: int = 16,
        hosts_min: int = 4, hosts_max: int = 12,
        ports_min: int = 2, ports_max: int = 6,
        timeout_min: float = 1.5, timeout_max: float = 5.0,
        # Limiares de decisão
        slow_threshold_sec: float = 40.0,
        very_slow_threshold_sec: float = 60.0,
        timeout_ratio_high: float = 0.30,
        timeout_ratio_moderate: float = 0.10,
        fast_threshold_sec: float = 12.0,
        timeout_ratio_low: float = 0.05,
        # Histerese
        cooldown_batches: int = 2,
        good_batches_to_increase: int = 3,
        slow_batches_to_cut_hosts: int = 2,
        slow_batches_to_cut_ports: int = 3,
    ):
        # Parâmetros atuais (mutáveis)
        self.batch = batch_size
        self.hosts = host_workers
        self.ports = port_workers
        self.timeout = socket_timeout

        # Limites
        self._limits = {
            "batch": (batch_min, batch_max),
            "hosts": (hosts_min, hosts_max),
            "ports": (ports_min, ports_max),
            "timeout": (timeout_min, timeout_max),
        }

        # Limiares
        self._slow_sec = slow_threshold_sec
        self._very_slow_sec = very_slow_threshold_sec
        self._timeout_high = timeout_ratio_high
        self._timeout_moderate = timeout_ratio_moderate
        self._fast_sec = fast_threshold_sec
        self._timeout_low = timeout_ratio_low

        # Histerese
        self._cooldown_duration = cooldown_batches
        self._good_needed = good_batches_to_increase
        self._slow_for_hosts = slow_batches_to_cut_hosts
        self._slow_for_ports = slow_batches_to_cut_ports

        # Estado interno
        self._cooldown = 0
        self._consecutive_good = 0
        self._consecutive_slow = 0

    def _clamp(self) -> None:
        """Garante que todos os parâmetros estão dentro dos limites."""
        bmin, bmax = self._limits["batch"]
        hmin, hmax = self._limits["hosts"]
        pmin, pmax = self._limits["ports"]
        tmin, tmax = self._limits["timeout"]

        self.batch = max(bmin, min(bmax, int(self.batch)))
        self.hosts = max(hmin, min(hmax, int(self.hosts)))
        self.ports = max(pmin, min(pmax, int(self.ports)))
        self.timeout = max(tmin, min(tmax, float(self.timeout)))

    def _apply_reduction(self, attr: str, factor: float, msg: str) -> Tuple[bool, str]:
        """Aplica redução percentual a um atributo, respeitando limites."""
        current = getattr(self, attr)
        min_val = self._limits[attr][0]
        if current <= min_val:
            return False, ""
        new_val = max(min_val, int(current * factor))
        if attr == "ports":
            new_val = max(min_val, current - 1)  # Portas: decremento de 1
        setattr(self, attr, new_val)
        self._clamp()
        self._cooldown = self._cooldown_duration
        return True, msg.format(val=getattr(self, attr))

    def suggest(self, batch_duration: float, timeouts: int, completed: int) -> Tuple[bool, str]:
        """
        Analisa o lote e sugere ajustes nos parâmetros.

        Args:
            batch_duration: Duração do lote em segundos.
            timeouts: Número de hosts com timeout no lote.
            completed: Total de hosts processados no lote.

        Returns:
            Tupla (ajustou, mensagem). Se ajustou=False, nenhuma mudança.
        """
        if completed <= 0:
            return False, ""

        timeout_ratio = timeouts / max(1, completed)
        is_slow = batch_duration > self._slow_sec
        is_very_slow = batch_duration > self._very_slow_sec
        is_fast = batch_duration <= self._fast_sec
        low_timeouts = timeout_ratio <= self._timeout_low

        # Contadores de tendência
        self._consecutive_slow = self._consecutive_slow + 1 if is_slow else 0

        # Em cooldown: apenas conta lotes bons
        if self._cooldown > 0:
            self._cooldown -= 1
            if is_fast and low_timeouts:
                self._consecutive_good += 1
            else:
                self._consecutive_good = 0
            return False, ""

        # --- REDUÇÃO (prioridade: batch > hosts > portas > timeout) ---

        if is_very_slow:
            ok, msg = self._apply_reduction(
                "batch", 0.85,
                "reduzindo batch->{val} (muito lento: " + f"{batch_duration:.1f}s)"
            )
            if ok:
                return True, msg

        if is_slow and timeout_ratio >= self._timeout_moderate:
            ok, msg = self._apply_reduction(
                "batch", 0.85,
                "reduzindo batch->{val} (lento + timeouts " + f"{timeout_ratio:.0%})"
            )
            if ok:
                return True, msg

        if is_slow and self._consecutive_slow >= self._slow_for_hosts:
            ok, msg = self._apply_reduction(
                "hosts", 0.85,
                "reduzindo hosts->{val} (lentos " + f"{self._consecutive_slow}x)"
            )
            if ok:
                return True, msg

        if is_slow and self._consecutive_slow >= self._slow_for_ports:
            ok, msg = self._apply_reduction(
                "ports", 1.0,  # fator ignorado, portas decrementam por 1
                "reduzindo portas->{val} (lentos " + f"{self._consecutive_slow}x)"
            )
            if ok:
                return True, msg

        # Aumenta timeout se há muitos timeouts reais
        if timeout_ratio >= self._timeout_moderate and self.timeout < self._limits["timeout"][1]:
            self.timeout = min(self._limits["timeout"][1], self.timeout + 0.5)
            self._clamp()
            self._cooldown = self._cooldown_duration
            return True, f"aumentando timeout->{self.timeout:.1f}s (timeouts {timeout_ratio:.0%})"

        # --- AUMENTO (gradual, conservador) ---

        if is_fast and low_timeouts:
            self._consecutive_good += 1
        else:
            self._consecutive_good = 0

        if self._consecutive_good >= self._good_needed:
            for attr in ("batch", "hosts", "ports"):
                current = getattr(self, attr)
                max_val = self._limits[attr][1]
                if current < max_val:
                    setattr(self, attr, min(max_val, current + 1))
                    self._consecutive_good = 0
                    self._cooldown = self._cooldown_duration
                    self._clamp()
                    return True, (
                        f"aumentando {attr}->{getattr(self, attr)} "
                        f"(estável {self._good_needed} lotes)"
                    )

        return False, ""


# ==============================
# Verificação de CVEs (centralizada)
# ==============================

def _run_cve_checks(hosts: Dict[str, dict]) -> None:
    """
    Verifica CVEs para todos os hosts com banners, em uma única passada.

    Centralizar aqui evita o problema anterior onde CVEs eram verificados
    tanto em scan.py quanto em __main__.py (trabalho duplicado).

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
        from cve import carregar_base_local_cves, verificar_vulnerabilidades_em_banners

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

def _scan_batch(
    batch_ips: List,
    scan_fn,
    oui_table: dict,
    port_workers: int,
    socket_timeout: float,
    results: Dict[str, dict],
    progress_batch,
    progress_total,
) -> Tuple[int, int]:
    """
    Varre um lote de IPs em paralelo e coleta resultados.

    Args:
        batch_ips: Lista de IPs do lote.
        scan_fn: Função de scan por host (scan.scan_host).
        oui_table: Tabela OUI de fabricantes.
        port_workers: Workers para port scan por host.
        socket_timeout: Timeout de socket.
        results: Dicionário de resultados (modificado in-place).
        progress_batch: Barra de progresso do lote.
        progress_total: Barra de progresso total.

    Returns:
        Tupla (completed, timeouts) do lote.
    """
    timeouts = 0
    completed = 0
    host_workers = len(batch_ips)  # Máximo = tamanho do lote

    with ThreadPoolExecutor(max_workers=host_workers) as executor:
        futures = {
            executor.submit(scan_fn, ip, oui_table, port_workers, socket_timeout): ip
            for ip in batch_ips
        }

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
            completed += 1
            progress_batch.update(1)
            progress_total.update(1)

    return completed, timeouts


# ==============================
# Fluxo principal
# ==============================

def main():
    """
    Ponto de entrada principal do verificador de hosts.

    Fluxo:
    1. Carrega configuração (auto_configurar)
    2. Atualiza base NVD se necessário
    3. Carrega tabela OUI
    4. Solicita range de IPs ao usuário
    5. Varre hosts em lotes com governança adaptativa
    6. Verifica CVEs nos banners coletados
    7. Exibe relatório e oferece exportação CSV
    """
    # 1) Configuração
    config = auto_configurar()
    batch_size = max(1, int(config["batch_size"]))
    skip_cve = bool(config["skip_cve"])
    skip_nvd_update = bool(config["skip_nvd_update"])
    adaptive = bool(config.get("adaptive", True))

    # Propaga configuração para scan.py via ENV (lido no import)
    os.environ["VH_MAX_SOCKETS"] = str(int(config["max_sockets"]))
    os.environ["VH_RESOLVE_HOSTNAME"] = "1" if config["resolve_hostname"] else "0"
    os.environ["VH_TCP_ONLY"] = "1" if config["tcp_only"] else "0"

    from scan import scan_host  # Import tardio após configurar ENV

    # Log de configuração efetiva
    console.print(
        "[bold green]AutoConfig:[/bold green] "
        f"modo={config['mode']} | "
        f"hosts_threads={config['max_workers_hosts']} | "
        f"portas_threads={config['max_workers_portas']} | "
        f"timeout={config['timeout_socket']}s | "
        f"batch={batch_size} | "
        f"max_sockets={config['max_sockets']} | "
        f"resolve_hostname={int(config['resolve_hostname'])} | "
        f"tcp_only={int(config['tcp_only'])} | "
        f"skip_cve={int(skip_cve)} | "
        f"skip_nvd_update={int(skip_nvd_update)} | "
        f"adaptive={int(adaptive)}"
    )

    # 2) Atualização NVD
    if not skip_nvd_update and _needs_nvd_update():
        console.print("\n[bold yellow]Atualizando base de vulnerabilidades da NVD...[/bold yellow]")
        try:
            atualizar_base_nvd()
            _record_nvd_update()
            console.print("[green]Base NVD atualizada com sucesso.[/green]\n")
        except Exception as e:
            console.print(f"[red]Falha ao atualizar base NVD: {e}[/red]")
    else:
        console.print("\n[bold cyan]Pulando atualização da NVD (recente ou desabilitada).[/bold cyan]\n")

    # 3) Tabela OUI
    oui_table = carregar_tabela_oui()

    # 4) Input do usuário
    print("\n==============================================")
    print(" Verificador de Hosts com Auditoria de Segurança")
    print("==============================================\n")

    try:
        ip_base, start, end = solicitar_dados_input()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelado pelo usuário.[/yellow]")
        return

    if end < start:
        console.print("[red]Intervalo inválido: fim < início.[/red]")
        return

    ip_list = [f"{ip_base}.{i}" for i in range(start, end + 1)]
    if not ip_list:
        console.print("[red]Nenhum IP no intervalo informado.[/red]")
        return

    # 5) Varredura com governança adaptativa
    results: Dict[str, dict] = {}
    spinner = _start_spinner("Verificando hosts e portas")

    host_workers = int(config["max_workers_hosts"])
    port_workers = int(config["max_workers_portas"])
    socket_timeout = float(config["timeout_socket"])

    governor = AdaptiveGovernor(
        batch_size=batch_size,
        host_workers=host_workers,
        port_workers=port_workers,
        socket_timeout=socket_timeout,
        slow_threshold_sec=max(40.0, socket_timeout * 8),
        very_slow_threshold_sec=max(60.0, socket_timeout * 12),
        fast_threshold_sec=max(12.0, socket_timeout * 3),
    )

    total_ips = len(ip_list)
    progress_total = tqdm(total=total_ips, desc="Total", ncols=100, position=0, dynamic_ncols=True)

    try:
        pos = 0
        batch_idx = 0

        while pos < total_ips:
            batch_idx += 1
            batch_end = min(total_ips, pos + batch_size)
            batch_ips = ip_list[pos:batch_end]
            pos = batch_end

            t0 = time.time()

            progress_batch = tqdm(
                total=len(batch_ips),
                desc=f"Lote {batch_idx} (hosts={host_workers},portas={port_workers},batch={batch_size})",
                ncols=100, position=1, leave=False, dynamic_ncols=True,
            )

            # Executor por lote (permite ajustar workers entre lotes)
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
                    completed += 1
                    progress_batch.update(1)
                    progress_total.update(1)

            progress_batch.close()
            duration = time.time() - t0

            # Governança: ajustar parâmetros se necessário
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
        try:
            progress_total.close()
        except Exception:
            pass

    # 6) Verificação de CVEs (centralizada, única passada)
    if not skip_cve:
        _run_cve_checks(results)
    else:
        console.print("[yellow]skip_cve=1: verificação de CVEs desativada.[/yellow]")

    # 7) Relatório
    table = gerar_tabela(results)
    console.print("\n[bold cyan]Resumo Final:[/bold cyan]")
    console.print(table)

    # 8) Exportação CSV
    try:
        save = input("\nDeseja exportar o resultado para CSV? (s/n): ").strip().lower()
    except KeyboardInterrupt:
        save = "n"

    if save == "s":
        try:
            path = input("Caminho para salvar (padrão: auditoria_hosts.csv): ").strip()
            path = path or "auditoria_hosts.csv"
        except KeyboardInterrupt:
            path = "auditoria_hosts.csv"
        exportar_csv(results, path)
        console.print(f"[green]Exportado para {path}[/green]")

    try:
        input("\nPressione Enter para sair...")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
