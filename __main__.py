"""
# __main__.py (governança adaptativa + progresso total e por lote)

- Presets conservadores vindos do config (features por modo: leve/completo).
- Spinner simples de atividade.
- Duas barras de progresso: TOTAL (contínua) e LOTE (reinicia por lote).
- Governança adaptativa bidirecional, menos agressiva:
  * Reduz batch/hosts/portas apenas quando lento de verdade
    ou quando há timeouts (com histerese/cooldown).
  * Aumenta devagar após lotes bons consecutivos.
- Atualização NVD opcional.
- Verificação de CVEs opcional (só se houver banners).

Autor: Luiz
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

# Caminhos NVD
CAMINHO_NVD = "nvd_data"
CAMINHO_REGISTRO_ATUALIZACAO = os.path.join(CAMINHO_NVD, "ultima_atualizacao.txt")
INTERVALO_DIAS_ATUALIZACAO = 7  # dias

console = Console()


# ==============================
# Utilidades NVD
# ==============================

def precisa_atualizar_nvd() -> bool:
    """True se passou o intervalo definido ou se o arquivo de verificação não existe."""
    try:
        if not os.path.exists(CAMINHO_REGISTRO_ATUALIZACAO):
            return True
        with open(CAMINHO_REGISTRO_ATUALIZACAO, "r", encoding="utf-8") as f:
            ultima_str = f.read().strip()
            ultima_data = datetime.strptime(ultima_str, "%Y-%m-%d")
        return datetime.now() - ultima_data > timedelta(days=INTERVALO_DIAS_ATUALIZACAO)
    except Exception:
        return True


def registrar_data_atualizacao() -> None:
    """Registra a data da última atualização da base NVD em arquivo."""
    os.makedirs(CAMINHO_NVD, exist_ok=True)
    with open(CAMINHO_REGISTRO_ATUALIZACAO, "w", encoding="utf-8") as f:
        f.write(datetime.now().strftime("%Y-%m-%d"))


# ==============================
# Spinner
# ==============================

def start_spinner(msg: str = "Processando..."):
    """Spinner leve em thread separada; retorna Event para parar."""
    stop_flag = threading.Event()
    spinner_cycle = itertools.cycle(["|", "/", "-", "\\"])

    def run_spinner():
        while not stop_flag.is_set():
            sys.stdout.write(f"\r{msg} {next(spinner_cycle)}")
            sys.stdout.flush()
            time.sleep(0.1)
        # limpar linha ao parar
        sys.stdout.write("\r" + " " * (len(msg) + 4) + "\r")
        sys.stdout.flush()

    t = threading.Thread(target=run_spinner, daemon=True)
    t.start()
    return stop_flag


# ==============================
# Governança adaptativa (menos agressiva)
# ==============================

class AdaptiveGovernor:
    """
    Governança com histerese/cooldown e critérios mais conservadores.
    - Reduz quando: lote MUITO lento OU (lento + timeouts).
    - Prioriza reduzir batch; só mexe em hosts/portas após N lotes lentos seguidos.
    - Sobe devagar após N lotes bons.
    - Timeout aumenta apenas se houver timeouts reais.
    """

    def __init__(
        self,
        batch_ini: int,
        hosts_ini: int,
        portas_ini: int,
        timeout_ini: float,
        # limites
        batch_min: int = 6,
        batch_max: int = 16,
        hosts_min: int = 4,
        hosts_max: int = 12,
        portas_min: int = 2,
        portas_max: int = 6,
        timeout_min: float = 1.5,
        timeout_max: float = 5.0,
        # critérios
        lote_lento_seg: float = 40.0,        # redes lentas não disparam corte cedo
        lote_muito_lento_seg: float = 60.0,  # muito lento => pode cortar batch mesmo sem timeout
        timeout_ratio_corta: float = 0.30,   # >30% timeouts = sufoco
        timeout_ratio_moderado: float = 0.10,# >10% já preocupa
        folga_seg: float = 12.0,             # lote rápido
        timeout_ratio_baixo: float = 0.05,   # <5% timeouts = ok
        # histerese/cooldown
        cool_down_lotes: int = 2,
        lotes_bons_para_subir: int = 3,
        # proteção contra “sanfona”
        max_cortes_por_lote: int = 1,
        consecutive_slow_to_cut_hosts: int = 2,
        consecutive_slow_to_cut_ports: int = 3,
    ):
        self.batch = batch_ini
        self.hosts = hosts_ini
        self.portas = portas_ini
        self.timeout = timeout_ini

        self.batch_min = batch_min
        self.batch_max = batch_max
        self.hosts_min = hosts_min
        self.hosts_max = hosts_max
        self.portas_min = portas_min
        self.portas_max = portas_max
        self.timeout_min = timeout_min
        self.timeout_max = timeout_max

        self.lote_lento_seg = lote_lento_seg
        self.lote_muito_lento_seg = lote_muito_lento_seg
        self.timeout_ratio_corta = timeout_ratio_corta
        self.timeout_ratio_moderado = timeout_ratio_moderado
        self.folga_seg = folga_seg
        self.timeout_ratio_baixo = timeout_ratio_baixo

        self.cool_down_lotes = cool_down_lotes
        self.lotes_bons_para_subir = lotes_bons_para_subir
        self.max_cortes_por_lote = max_cortes_por_lote
        self.consecutive_slow_to_cut_hosts = consecutive_slow_to_cut_hosts
        self.consecutive_slow_to_cut_ports = consecutive_slow_to_cut_ports

        self._cooldown = 0
        self._bons_consecutivos = 0
        self._lentos_consecutivos = 0

    def _clamp(self):
        self.batch = max(self.batch_min, min(self.batch_max, int(self.batch)))
        self.hosts = max(self.hosts_min, min(self.hosts_max, int(self.hosts)))
        self.portas = max(self.portas_min, min(self.portas_max, int(self.portas)))
        self.timeout = max(self.timeout_min, min(self.timeout_max, float(self.timeout)))

    def suggest(self, duracao_lote: float, timeouts: int, concluidos: int) -> Tuple[bool, str]:
        """Decide se ajusta e como. Retorna (ajustou, mensagem)."""
        if concluidos <= 0:
            return False, ""

        ratio_timeout = timeouts / max(1, concluidos)
        lote_lento = duracao_lote > self.lote_lento_seg
        lote_muito_lento = duracao_lote > self.lote_muito_lento_seg

        if lote_lento:
            self._lentos_consecutivos += 1
        else:
            self._lentos_consecutivos = 0

        # cooldown em andamento: apenas contabiliza "bons" e sai
        if self._cooldown > 0:
            self._cooldown -= 1
            if (duracao_lote <= self.folga_seg) and (ratio_timeout <= self.timeout_ratio_baixo):
                self._bons_consecutivos += 1
            else:
                self._bons_consecutivos = 0
            return False, ""

        # ======= REDUÇÃO =======

        # (A) Muito lento => reduz batch (15%) mesmo sem timeouts
        if lote_muito_lento and self.max_cortes_por_lote > 0:
            if self.batch > self.batch_min:
                self.batch = max(self.batch_min, int(self.batch * 0.85))
                self._clamp()
                self._cooldown = self.cool_down_lotes
                return True, f"reduzindo batch->{self.batch} (muito lento: {duracao_lote:.1f}s)"

        # (B) Lento + timeouts moderados => reduz batch (15%)
        if lote_lento and ratio_timeout >= self.timeout_ratio_moderado and self.max_cortes_por_lote > 0:
            if self.batch > self.batch_min:
                self.batch = max(self.batch_min, int(self.batch * 0.85))
                self._clamp()
                self._cooldown = self.cool_down_lotes
                return True, f"reduzindo batch->{self.batch} (lento e timeouts {ratio_timeout:.0%})"

        # (C) Após 2 lotes lentos seguidos => reduz hosts (15%)
        if lote_lento and self._lentos_consecutivos >= self.consecutive_slow_to_cut_hosts and self.max_cortes_por_lote > 0:
            if self.hosts > self.hosts_min:
                self.hosts = max(self.hosts_min, int(self.hosts * 0.85))
                self._clamp()
                self._cooldown = self.cool_down_lotes
                return True, f"reduzindo hosts->{self.hosts} (lentos {self._lentos_consecutivos}x)"

        # (D) Após 3 lotes lentos seguidos => reduz portas (-1)
        if lote_lento and self._lentos_consecutivos >= self.consecutive_slow_to_cut_ports and self.max_cortes_por_lote > 0:
            if self.portas > self.portas_min:
                self.portas = max(self.portas_min, self.portas - 1)
                self._clamp()
                self._cooldown = self.cool_down_lotes
                return True, f"reduzindo portas->{self.portas} (lentos {self._lentos_consecutivos}x)"

        # (E) Aumenta timeout só se houver timeouts reais
        if ratio_timeout >= self.timeout_ratio_moderado and self.timeout < self.timeout_max:
            self.timeout = min(self.timeout_max, self.timeout + 0.5)
            self._clamp()
            self._cooldown = self.cool_down_lotes
            return True, f"aumentando timeout->{self.timeout:.1f}s (timeouts {ratio_timeout:.0%})"

        # ======= AUMENTO (devagar) =======
        if (duracao_lote <= self.folga_seg) and (ratio_timeout <= self.timeout_ratio_baixo):
            self._bons_consecutivos += 1
        else:
            self._bons_consecutivos = 0

        if self._bons_consecutivos >= self.lotes_bons_para_subir:
            if self.batch < self.batch_max:
                self.batch = min(self.batch_max, self.batch + 1)
                self._bons_consecutivos = 0
                self._cooldown = self.cool_down_lotes
                self._clamp()
                return True, f"aumentando batch->{self.batch} (estável {self.lotes_bons_para_subir} lotes)"
            elif self.hosts < self.hosts_max:
                self.hosts = min(self.hosts_max, self.hosts + 1)
                self._bons_consecutivos = 0
                self._cooldown = self.cool_down_lotes
                self._clamp()
                return True, f"aumentando hosts->{self.hosts} (estável {self.lotes_bons_para_subir} lotes)"
            elif self.portas < self.portas_max:
                self.portas = min(self.portas_max, self.portas + 1)
                self._bons_consecutivos = 0
                self._cooldown = self.cool_down_lotes
                self._clamp()
                return True, f"aumentando portas->{self.portas} (estável {self.lotes_bons_para_subir} lotes)"

        return False, ""


# ==============================
# Fluxo principal
# ==============================

def main():
    """Ponto de entrada principal (parâmetros operacionais vêm do config)."""
    # 1) Config base
    config = auto_configurar()
    BATCH_SIZE = max(1, int(config["batch_size"]))
    SKIP_CVE = bool(config["skip_cve"])
    SKIP_NVD_UPDATE = bool(config["skip_nvd_update"])
    ADAPTIVE = bool(config.get("adaptive", True))

    # 2) Ajustar ENV antes de importar scan (compat com scan.py que lê ENV)
    os.environ["VH_MAX_SOCKETS"] = str(int(config["max_sockets"]))
    os.environ["VH_RESOLVE_HOSTNAME"] = "1" if config["resolve_hostname"] else "0"
    os.environ["VH_TCP_ONLY"] = "1" if config["tcp_only"] else "0"

    # 3) Import tardio do scan
    from scan import verificar_host  # noqa: E402

    # 4) Log de config efetiva
    console.print(
        "[bold green]AutoConfig:[/bold green] "
        f"modo={config['mode']} | "
        f"hosts_threads={config['max_workers_hosts']} | "
        f"portas_threads={config['max_workers_portas']} | "
        f"timeout={config['timeout_socket']}s | "
        f"batch={BATCH_SIZE} | "
        f"max_sockets={config['max_sockets']} | "
        f"resolve_hostname={int(config['resolve_hostname'])} | "
        f"tcp_only={int(config['tcp_only'])} | "
        f"skip_cve={int(SKIP_CVE)} | "
        f"skip_nvd_update={int(SKIP_NVD_UPDATE)} | "
        f"adaptive={int(ADAPTIVE)}"
    )

    # 5) NVD opcional
    if not SKIP_NVD_UPDATE and precisa_atualizar_nvd():
        console.print("\n[bold yellow]Atualizando base de vulnerabilidades da NVD...[/bold yellow]")
        console.print("[cyan]Verificando atualizações da base CVE...[/cyan]")
        try:
            atualizar_base_nvd()
            registrar_data_atualizacao()
            console.print("[green]Base NVD atualizada com sucesso.[/green]\n")
        except Exception as e:
            console.print(f"[red]Falha ao atualizar base NVD: {e}[/red]")
    else:
        console.print("\n[bold cyan]Pulando atualização da NVD (recente ou config.skip_nvd_update=1).[/bold cyan]\n")

    # 6) OUI e input
    fabricantes = carregar_tabela_oui()

    print("\n==============================================")
    print(" Verificador de Hosts com Auditoria de Segurança")
    print("==============================================\n")

    try:
        ip_base, inicio, fim = solicitar_dados_input()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelado pelo usuário.[/yellow]")
        return

    if fim < inicio:
        console.print("[red]Intervalo inválido: fim < início.[/red]")
        return

    lista_ips = [f"{ip_base}.{i}" for i in range(inicio, fim + 1)]
    if not lista_ips:
        console.print("[red]Nenhum IP no intervalo informado.[/red]")
        return

    # 7) Scanner com governança + DUAS barras (total e lote)
    status_dict: Dict[str, dict] = {}
    spinner_flag = start_spinner("Verificando hosts e portas")

    hosts_workers = int(config["max_workers_hosts"])
    portas_workers = int(config["max_workers_portas"])
    timeout_socket = float(config["timeout_socket"])

    # Governor com thresholds mais relaxados (rede lenta não vira “pânico”)
    gov = AdaptiveGovernor(
        batch_ini=BATCH_SIZE,
        hosts_ini=hosts_workers,
        portas_ini=portas_workers,
        timeout_ini=timeout_socket,
        batch_min=6, batch_max=16,
        hosts_min=4, hosts_max=12,
        portas_min=2, portas_max=6,
        timeout_min=1.5, timeout_max=5.0,
        lote_lento_seg=max(40.0, timeout_socket * 8),
        lote_muito_lento_seg=max(60.0, timeout_socket * 12),
        timeout_ratio_corta=0.30,
        timeout_ratio_moderado=0.10,
        folga_seg=max(12.0, timeout_socket * 3),
        timeout_ratio_baixo=0.05,
        cool_down_lotes=2,
        lotes_bons_para_subir=3,
        max_cortes_por_lote=1,
        consecutive_slow_to_cut_hosts=2,
        consecutive_slow_to_cut_ports=3,
    )

    total_ips = len(lista_ips)
    pbar_total = tqdm(total=total_ips, desc="Total", ncols=100, position=0, dynamic_ncols=True)

    try:
        pos = 0
        lote_idx = 0
        total = total_ips

        while pos < total:
            lote_idx += 1
            fim_i = min(total, pos + BATCH_SIZE)
            batch_ips = lista_ips[pos:fim_i]
            pos = fim_i

            t0 = time.time()
            timeouts = 0
            concluidos = 0

            pbar_lote = tqdm(
                total=len(batch_ips),
                desc=f"Lote {lote_idx} (hosts={hosts_workers},portas={portas_workers},batch={BATCH_SIZE})",
                ncols=100, position=1, leave=False, dynamic_ncols=True
            )

            # Executor por lote permite ajustar hosts dinamicamente
            with ThreadPoolExecutor(max_workers=hosts_workers) as executor:
                tarefas = {
                    executor.submit(
                        verificar_host,
                        ip,
                        fabricantes,
                        portas_workers,
                        timeout_socket,
                        {}
                    ): ip for ip in batch_ips
                }

                for future in as_completed(tarefas):
                    try:
                        resultado = future.result(timeout=(timeout_socket * 2) + 5)
                    except Exception as e:
                        timeouts += 1
                        ip_fut = tarefas[future]
                        resultado = {
                            "ip": ip_fut, "status": "OFFLINE", "nome": "N/D", "mac": "N/D",
                            "fabricante": "N/D", "so": "N/D", "portas": [], "banners": [],
                            "vulnerabilidades": [], "latencia": -1.0, "erro": str(e),
                        }
                    status_dict[resultado["ip"]] = resultado
                    concluidos += 1
                    pbar_lote.update(1)
                    pbar_total.update(1)

            pbar_lote.close()
            dur = time.time() - t0

            # ======= Governança: decidir ajuste =======
            if ADAPTIVE:
                ajustou, msg = gov.suggest(duracao_lote=dur, timeouts=timeouts, concluidos=concluidos)
                if ajustou:
                    # aplicar novos parâmetros
                    BATCH_SIZE = gov.batch
                    hosts_workers = gov.hosts
                    portas_workers = gov.portas
                    timeout_socket = gov.timeout
                    console.print(f"[yellow]Adaptando: {msg}[/yellow]")

    finally:
        spinner_flag.set()
        try:
            pbar_total.close()
        except Exception:
            pass

    # 8) CVEs (opcional e só com banners)
    if not SKIP_CVE:
        tem_banner = any(v.get("banners") for v in status_dict.values())
        if tem_banner:
            console.print("\n[bold cyan]Calculando CVEs (CPE+faixa de versão)...[/bold cyan]")
            try:
                from cve import carregar_base_local_cves, verificar_vulnerabilidades_em_banners
                carregar_base_local_cves()
                for host in status_dict.values():
                    if host.get("banners"):
                        confirmadas, suspeitas = verificar_vulnerabilidades_em_banners(
                            host["banners"], detalhado=True, base_cves={}
                        )
                        host["vulnerabilidades"] = [
                            *confirmadas, *[f"{c} (suspeita)" for c in suspeitas]
                        ]
            except Exception as e:
                console.print(f"[red]Falha ao calcular CVEs: {e}[/red]")
        else:
            console.print("[yellow]Nenhum banner coletado; pulando verificação de CVEs.[/yellow]")
    else:
        console.print("[yellow]config.skip_cve=1: verificação de CVEs desativada.[/yellow]")

    # 9) Relatório
    tabela = gerar_tabela(status_dict)
    console.print("\n[bold cyan]Resumo Final:[/bold cyan]")
    console.print(tabela)

    # 10) CSV
    try:
        salvar = input("\nDeseja exportar o resultado para CSV? (s/n): ").strip().lower()
    except KeyboardInterrupt:
        salvar = "n"

    if salvar == "s":
        try:
            caminho = input("Caminho para salvar (padrão: auditoria_hosts.csv): ").strip() or "auditoria_hosts.csv"
        except KeyboardInterrupt:
            caminho = "auditoria_hosts.csv"
        exportar_csv(status_dict, caminho)
        console.print(f"[green]Exportado para {caminho}[/green]")

    try:
        input("\nPressione Enter para sair...")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
