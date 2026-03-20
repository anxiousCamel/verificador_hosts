"""
# relatorio.py — Geração de relatórios da auditoria de rede

## Descrição
Gera relatórios visuais e exportações dos resultados da varredura:
- Tabela colorida no terminal via Rich (cores por criticidade)
- Exportação CSV com separador ';' (compatível com Excel em locales PT-BR)

## Cores aplicadas
- **Status**: verde (ONLINE) / vermelho (OFFLINE)
- **Portas**: vermelho (críticas: SSH, Telnet, RDP, SMB, etc.) / azul (outras)
- **Latência**: verde (<10ms) / amarelo (<50ms) / laranja (<150ms) / vermelho (>150ms)
- **MAC**: ciano (detectado) / cinza (N/D)

## Autor
Luiz
"""

from rich.console import Console
from rich.table import Table
from rich import box
import csv

from scan import CRITICAL_PORTS

console = Console()


def gerar_tabela(status_dict: dict) -> Table:
    """
    Gera tabela Rich colorida com os resultados da auditoria.

    Args:
        status_dict: Dicionário IP -> dados do host (gerado pelo scanner).

    Returns:
        rich.table.Table formatada para exibição no terminal.
    """
    table = Table(title="Status dos Hosts (Auditoria de Segurança)", box=box.ROUNDED)

    table.add_column("IP", style="bold", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("Hostname")
    table.add_column("MAC")
    table.add_column("Latência")
    table.add_column("Fabricante")
    table.add_column("SO")
    table.add_column("Portas")
    table.add_column("Banners")
    table.add_column("Vulnerabilidades")

    # Ordena por octeto numérico (não alfabeticamente)
    sorted_ips = sorted(status_dict, key=lambda ip: tuple(map(int, ip.split("."))))

    for ip in sorted_ips:
        host = status_dict[ip]

        # Formatação condicional por campo
        ip_fmt = (
            f"[yellow]{ip}[/yellow]" if host["status"] == "ONLINE"
            else f"[grey30]{ip}[/grey30]"
        )

        status_fmt = (
            "[green]ONLINE[/green]" if host["status"] == "ONLINE"
            else "[red]OFFLINE[/red]"
        )

        hostname_fmt = (
            f"[grey30]{host['nome']}[/grey30]"
            if host["nome"] in ("Nome N/D", "-", "N/D")
            else host["nome"]
        )

        mac_fmt = _format_mac(host["mac"])

        fab_fmt = (
            f"[grey30]{host['fabricante']}[/grey30]"
            if host["fabricante"] in ("Fabricante N/D", "-", "N/D")
            else host["fabricante"]
        )

        latency_fmt = _format_latency(host["latencia"])

        ports_fmt = _format_ports(host["portas"])

        banners_fmt = ", ".join(host["banners"]) if host["banners"] else "-"
        vulns_fmt = ", ".join(host.get("vulnerabilidades", [])) or "-"

        table.add_row(
            ip_fmt, status_fmt, hostname_fmt, mac_fmt, latency_fmt,
            fab_fmt, host["so"], ports_fmt, banners_fmt, vulns_fmt,
        )

    return table


def _format_mac(mac: str) -> str:
    """Aplica cor ao MAC: ciano se detectado, vermelho se 'MAC N/D', cinza se '-'."""
    if mac == "MAC N/D":
        return f"[red]{mac}[/red]"
    if mac in ("-", "N/D"):
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


def exportar_csv(status_dict: dict, caminho: str = "auditoria_hosts.csv") -> None:
    """
    Exporta resultados da auditoria para arquivo CSV.

    Usa separador ';' para compatibilidade com Excel em locales que
    usam ',' como separador decimal.

    Args:
        status_dict: Dicionário IP -> dados do host.
        caminho: Caminho do arquivo de saída.
    """
    try:
        with open(caminho, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f, delimiter=";")
            writer.writerow([
                "IP", "Status", "Hostname", "MAC", "Fabricante",
                "SO", "Portas", "Banners", "Vulnerabilidades", "Latência (ms)",
            ])

            for ip, host in status_dict.items():
                writer.writerow([
                    ip,
                    host["status"],
                    host["nome"],
                    host["mac"],
                    host["fabricante"],
                    host["so"],
                    ", ".join(host["portas"]),
                    ", ".join(host["banners"]),
                    ", ".join(host.get("vulnerabilidades", [])),
                    host["latencia"],
                ])
    except Exception as e:
        console.print(f"[red]Erro ao exportar CSV:[/red] {e}")
