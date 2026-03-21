"""
# src/services/reporter.py — Geração de relatórios da auditoria de rede

## Descrição
Gera relatórios visuais e exportações dos resultados da varredura:
- Classificação de risco por host (Crítico / Alto / Médio / Baixo / Info)
- Tabela colorida no terminal via Rich (responsiva, adapta ao terminal)
- Exportação CSV com separador ';' (compatível com Excel em locales PT-BR)

## Classificação de Risco
Cada host recebe um score baseado em:
- CVEs confirmados: +10 pontos cada
- CVEs suspeitos: +3 pontos cada
- Portas críticas abertas (SSH, Telnet, RDP, SMB): +5 por porta
- Serviços com versão antiga detectada: +5

Score → Nível:
- >= 50: CRÍTICO (vermelho)
- >= 25: ALTO (laranja)
- >= 10: MÉDIO (amarelo)
- >= 1:  BAIXO (azul)
- 0:     INFO (cinza)

Camada: services
Dependências: src.services.scan_service (apenas CRITICAL_PORTS — constante)
"""

from rich.console import Console
from rich.table import Table
from rich import box
import csv
import re
from typing import Dict, Tuple, List

from src.services.scan_service import CRITICAL_PORTS

console = Console()

# Portas que indicam alto risco se abertas publicamente
HIGH_RISK_PORTS = {
    23,     # Telnet (cleartext)
    3389,   # RDP
    5900,   # VNC
    135,    # RPC
    445,    # SMB
    3306,   # MySQL
    5432,   # PostgreSQL
    6379,   # Redis
    27017,  # MongoDB
    11211,  # Memcached
}


# ==============================
# Classificação de risco
# ==============================

def calcular_risco(host: dict) -> Tuple[int, str]:
    """
    Calcula score e nível de risco para um host.

    Returns:
        Tupla (score, nivel) onde nivel é "CRÍTICO", "ALTO", "MÉDIO", "BAIXO" ou "INFO".
    """
    if host.get("status") != "ONLINE":
        return (0, "INFO")

    score = 0
    vulns = host.get("vulnerabilidades", [])

    for v in vulns:
        if "(suspeita)" in str(v):
            score += 3
        else:
            score += 10

    for port_str in host.get("portas", []):
        try:
            port_num = int(port_str)
            if port_num in HIGH_RISK_PORTS:
                score += 5
            elif port_num in CRITICAL_PORTS:
                score += 2
        except ValueError:
            pass

    if score >= 50:
        return (score, "CRÍTICO")
    if score >= 25:
        return (score, "ALTO")
    if score >= 10:
        return (score, "MÉDIO")
    if score >= 1:
        return (score, "BAIXO")
    return (0, "INFO")


def classificar_hosts(status_dict: dict) -> List[Tuple[str, dict, int, str]]:
    """
    Classifica e ordena hosts por risco (maior primeiro).

    Returns:
        Lista de (ip, host_data, score, nivel) ordenada por score decrescente.
    """
    classified = []
    for ip, host in status_dict.items():
        score, nivel = calcular_risco(host)
        host["_risk_score"] = score
        host["_risk_level"] = nivel
        classified.append((ip, host, score, nivel))

    classified.sort(key=lambda x: (-x[2], x[0]))
    return classified


def _format_risk(score: int, nivel: str) -> str:
    """Formata nível de risco com cor."""
    colors = {
        "CRÍTICO": "bold red",
        "ALTO": "orange3",
        "MÉDIO": "yellow",
        "BAIXO": "blue",
        "INFO": "grey58",
    }
    color = colors.get(nivel, "white")
    return f"[{color}]{nivel} ({score})[/{color}]"


# ==============================
# Tabela principal (responsiva)
# ==============================

def gerar_tabela(status_dict: dict) -> Table:
    """
    Gera tabela Rich colorida com classificação de risco.

    A tabela adapta-se à largura do terminal:
    - Colunas de CVE mostram contagem + top 5 ao invés da lista completa
    - Banners são truncados para caber
    - overflow="fold" permite quebra de linha em colunas longas

    Args:
        status_dict: Dicionário IP -> dados do host (gerado pelo scanner).

    Returns:
        rich.table.Table formatada para exibição no terminal.
    """
    classified = classificar_hosts(status_dict)

    table = Table(
        title="Auditoria de Segurança — Hosts por Risco",
        box=box.SIMPLE_HEAVY,
        expand=True,
        show_lines=True,
    )

    table.add_column("Risco", style="bold", no_wrap=True, width=14)
    table.add_column("IP", style="bold", no_wrap=True, width=15)
    table.add_column("Status", style="bold", width=7)
    table.add_column("SO", width=12, overflow="fold")
    table.add_column("MAC", width=17, no_wrap=True)
    table.add_column("Latência", width=9, no_wrap=True)
    table.add_column("Fabricante", width=18, overflow="fold")
    table.add_column("Portas", width=20, overflow="fold")
    table.add_column("Banners", width=28, overflow="fold")
    table.add_column("CVEs", overflow="fold")

    for ip, host, score, nivel in classified:
        risk_fmt = _format_risk(score, nivel)

        ip_fmt = (
            f"[yellow]{ip}[/yellow]" if host["status"] == "ONLINE"
            else f"[grey30]{ip}[/grey30]"
        )

        status_fmt = (
            "[green]ONLINE[/green]" if host["status"] == "ONLINE"
            else "[red]OFFLINE[/red]"
        )

        mac_fmt = _format_mac(host["mac"])

        fab_fmt = (
            f"[grey30]{host['fabricante']}[/grey30]"
            if host["fabricante"] in ("Fabricante N/D", "-", "N/D")
            else host["fabricante"]
        )

        latency_fmt = _format_latency(host["latencia"])
        ports_fmt = _format_ports(host["portas"])
        banners_fmt = _format_banners(host["banners"])
        vulns_fmt = _format_vulns(host.get("vulnerabilidades", []))

        table.add_row(
            risk_fmt, ip_fmt, status_fmt, host["so"], mac_fmt,
            latency_fmt, fab_fmt, ports_fmt, banners_fmt, vulns_fmt,
        )

    return table


# ==============================
# Resumo de risco
# ==============================

def gerar_resumo_risco(status_dict: dict) -> str:
    """Gera resumo textual da classificação de risco."""
    counts = {"CRÍTICO": 0, "ALTO": 0, "MÉDIO": 0, "BAIXO": 0, "INFO": 0}
    for host in status_dict.values():
        nivel = host.get("_risk_level", "INFO")
        counts[nivel] = counts.get(nivel, 0) + 1

    lines = ["[bold magenta]Resumo de Risco:[/bold magenta]"]
    if counts["CRÍTICO"]:
        lines.append(f"  [bold red]CRÍTICO: {counts['CRÍTICO']} hosts[/bold red]")
    if counts["ALTO"]:
        lines.append(f"  [orange3]ALTO:    {counts['ALTO']} hosts[/orange3]")
    if counts["MÉDIO"]:
        lines.append(f"  [yellow]MÉDIO:   {counts['MÉDIO']} hosts[/yellow]")
    if counts["BAIXO"]:
        lines.append(f"  [blue]BAIXO:   {counts['BAIXO']} hosts[/blue]")
    if counts["INFO"]:
        lines.append(f"  [grey58]INFO:    {counts['INFO']} hosts[/grey58]")

    total_vulns = sum(
        len(h.get("vulnerabilidades", []))
        for h in status_dict.values()
    )
    confirmed = sum(
        1 for h in status_dict.values()
        for v in h.get("vulnerabilidades", [])
        if "(suspeita)" not in str(v)
    )
    suspected = total_vulns - confirmed
    lines.append(
        f"  [dim]Total CVEs: {total_vulns} "
        f"({confirmed} confirmados, {suspected} suspeitos)[/dim]"
    )

    return "\n".join(lines)


# ==============================
# Formatadores auxiliares
# ==============================

def _format_mac(mac: str) -> str:
    """Aplica cor ao MAC: ciano se detectado, cinza se N/D."""
    if mac in ("MAC N/D", "-", "N/D"):
        return f"[grey30]{mac}[/grey30]"
    return f"[bold cyan]{mac}[/bold cyan]"


def _format_latency(lat: float) -> str:
    """Aplica cor à latência por faixa: verde/amarelo/laranja/vermelho."""
    if lat == -1:
        return "[grey58]-[/grey58]"
    if lat <= 10:
        return f"[green]{lat:.1f} ms[/green]"
    if lat <= 50:
        return f"[yellow]{lat:.1f} ms[/yellow]"
    if lat <= 150:
        return f"[orange3]{lat:.1f} ms[/orange3]"
    return f"[red]{lat:.1f} ms[/red]"


def _format_ports(ports: list) -> str:
    """Portas críticas em vermelho, demais em azul."""
    if not ports:
        return "-"
    formatted = []
    for port_str in ports:
        try:
            port_num = int(port_str)
            color = "red" if port_num in CRITICAL_PORTS else "blue"
            formatted.append(f"[{color}]{port_str}[/{color}]")
        except ValueError:
            formatted.append(port_str)
    return ", ".join(formatted)


def _format_banners(banners: list) -> str:
    """Formata banners de forma compacta: só mostra o campo Server/versão."""
    if not banners:
        return "-"
    compact = []
    for entry in banners:
        parts = entry.split(":", 1)
        if len(parts) == 2:
            port, banner = parts[0], parts[1]
            # Extract just the server identification
            server_match = re.search(
                r"(?:Server:\s*|SSH-\S+\s+)(\S+(?:\s+\S+)?)", banner
            )
            if server_match:
                compact.append(f"{port}:{server_match.group(1)}")
            elif banner.strip() and banner.strip() != "-":
                # Truncate long banners
                short = banner.strip()[:40]
                if len(banner.strip()) > 40:
                    short += "..."
                compact.append(f"{port}:{short}")
            else:
                compact.append(f"{port}:-")
        else:
            compact.append(entry[:50])
    return "\n".join(compact)


def _format_vulns(vulns: list) -> str:
    """Formata CVEs: mostra contagem + top items, separando confirmados de suspeitos."""
    if not vulns:
        return "[grey58]-[/grey58]"

    confirmed = [v for v in vulns if "(suspeita)" not in str(v)]
    suspected = [v for v in vulns if "(suspeita)" in str(v)]

    parts = []

    if confirmed:
        if len(confirmed) <= 5:
            parts.append(
                "[bold red]" + ", ".join(confirmed) + "[/bold red]"
            )
        else:
            top5 = ", ".join(confirmed[:5])
            parts.append(
                f"[bold red]{top5}[/bold red]\n"
                f"[red]+{len(confirmed) - 5} mais[/red]"
            )

    if suspected:
        if len(suspected) <= 3:
            clean = [v.replace(" (suspeita)", "") for v in suspected]
            parts.append(
                "[yellow]" + ", ".join(clean) + " (suspeitas)[/yellow]"
            )
        else:
            parts.append(
                f"[yellow]{len(suspected)} CVEs suspeitas[/yellow]"
            )

    return "\n".join(parts)


# ==============================
# Exportação CSV
# ==============================

def exportar_csv(status_dict: dict, caminho: str = "auditoria_hosts.csv") -> None:
    """
    Exporta resultados da auditoria para arquivo CSV com classificação de risco.

    Usa separador ';' para compatibilidade com Excel em locales PT-BR.
    Hosts ordenados por risco (maior primeiro).

    Args:
        status_dict: Dicionário IP -> dados do host.
        caminho: Caminho do arquivo de saída.
    """
    try:
        classified = classificar_hosts(status_dict)

        with open(caminho, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "IP", "Status", "Risco", "Score", "Hostname", "MAC",
                "Fabricante", "SO", "Portas", "Banners",
                "CVEs Confirmados", "CVEs Suspeitos", "Latência (ms)",
            ])

            for ip, host, score, nivel in classified:
                confirmed = [
                    v for v in host.get("vulnerabilidades", [])
                    if "(suspeita)" not in str(v)
                ]
                suspected = [
                    v.replace(" (suspeita)", "")
                    for v in host.get("vulnerabilidades", [])
                    if "(suspeita)" in str(v)
                ]
                writer.writerow([
                    ip,
                    host["status"],
                    nivel,
                    score,
                    host["nome"],
                    host["mac"],
                    host["fabricante"],
                    host["so"],
                    ", ".join(host["portas"]),
                    ", ".join(host["banners"]),
                    ", ".join(confirmed),
                    ", ".join(suspected),
                    host["latencia"],
                ])
    except Exception as e:
        console.print(f"[red]Erro ao exportar CSV:[/red] {e}")
