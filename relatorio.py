"""
# relatorio.py

## Descrição
Este módulo é responsável por gerar relatórios visuais e exportações dos resultados
da auditoria de rede realizada pelo sistema.

### Funcionalidades:
- Exibe os dados dos hosts em uma tabela colorida no terminal usando `rich`.
- Aplica cores específicas para status, MAC, SO, portas críticas, banners e latência.
- Exporta os dados para um arquivo `.csv` com separador `;`.

### Integração:
Este módulo depende do dicionário de status (`status_dict`) construído pelo scanner.
Utiliza também a constante `PORTAS_CRITICAS` do módulo `scan`.

## Autor
Luiz

## Dependências
- rich.console
- rich.table
- rich.box
- csv
"""

from rich.console import Console
from rich.table import Table
from rich import box
import csv

from scan import PORTAS_CRITICAS

console = Console()


def gerar_tabela(status_dict):
    """
    Gera uma tabela visual no terminal com os dados da auditoria de rede.

    Parâmetros:
        status_dict (dict): Dicionário contendo os dados coletados por IP.

    Retorna:
        Table (rich.table.Table): Tabela formatada para visualização no terminal.
    """
    tabela = Table(title="Status dos Hosts (Auditoria de Segurança)", box=box.ROUNDED)

    tabela.add_column("IP", style="bold", no_wrap=True)
    tabela.add_column("Status", style="bold")
    tabela.add_column("Hostname")
    tabela.add_column("MAC")
    tabela.add_column("Latência")
    tabela.add_column("Fabricante")
    tabela.add_column("SO")
    tabela.add_column("Portas")
    tabela.add_column("Banners")
    tabela.add_column("Vulnerabilidades")

    # Ordena os IPs corretamente (não alfabeticamente)
    for ip in sorted(status_dict, key=lambda ip: tuple(map(int, ip.split(".")))):
        s = status_dict[ip]

        # === Formatação de colunas ===
        status_color = "[green]ONLINE[/green]" if s["status"] == "ONLINE" else "[red]OFFLINE[/red]"

        nome_fmt = (
            f"[grey30]{s['nome']}[/grey30]"
            if s["nome"] in ["Nome N/D", "-"]
            else s["nome"]
        )

        mac_fmt = (
            f"[red]{s['mac']}[/red]"
            if s["mac"] == "MAC N/D"
            else f"[grey30]{s['mac']}[/grey30]"
            if s["mac"] == "-"
            else f"[bold cyan]{s['mac']}[/bold cyan]"
        )

        fab_fmt = (
            f"[grey30]{s['fabricante']}[/grey30]"
            if s["fabricante"] in ["Fabricante N/D", "-"]
            else s["fabricante"]
        )

        ip_fmt = (
            f"[yellow]{ip}[/yellow]"
            if s["status"] == "ONLINE"
            else f"[grey30]{ip}[/grey30]"
        )

        # Porta crítica em vermelho, outras em azul
        portas_fmt = (
            ", ".join(
                f"[red]{p}[/red]" if int(p) in PORTAS_CRITICAS else f"[blue]{p}[/blue]"
                for p in s["portas"]
            )
            if s["portas"]
            else "-"
        )

        # Cores por faixa de latência
        lat = s["latencia"]
        if lat == -1:
            latencia_fmt = "[grey58]-[/grey58]"
        elif lat <= 10:
            latencia_fmt = f"[green]{lat:.1f} ms[/green]"
        elif lat <= 50:
            latencia_fmt = f"[yellow]{lat:.1f} ms[/yellow]"
        elif lat <= 150:
            latencia_fmt = f"[orange3]{lat:.1f} ms[/orange3]"
        else:
            latencia_fmt = f"[red]{lat:.1f} ms[/red]"

        banners_fmt = ", ".join(s["banners"]) if s["banners"] else "-"
        vulns_fmt = ", ".join(s.get("vulnerabilidades", [])) if s.get("vulnerabilidades") else "-"

        # Adiciona linha na tabela
        tabela.add_row(
            ip_fmt, status_color, nome_fmt, mac_fmt, latencia_fmt,
            fab_fmt, s["so"], portas_fmt, banners_fmt, vulns_fmt
        )

    return tabela


def exportar_csv(status_dict, caminho="auditoria_hosts.csv"):
    """
    Exporta os dados da auditoria para um arquivo CSV.

    Parâmetros:
        status_dict (dict): Dicionário contendo os dados por IP.
        caminho (str): Caminho do arquivo de saída (padrão: auditoria_hosts.csv).
    """
    try:
        with open(caminho, "w", newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';')
            writer.writerow([
                "IP", "Status", "Hostname", "MAC", "Fabricante",
                "SO", "Portas", "Banners", "Vulnerabilidades", "Latência (ms)"
            ])

            for ip, s in status_dict.items():
                portas_texto = ", ".join(s["portas"])
                banners_texto = ", ".join(s["banners"])
                vulns_texto = ", ".join(s.get("vulnerabilidades", []))

                writer.writerow([
                    ip, s["status"], s["nome"], s["mac"], s["fabricante"],
                    s["so"], portas_texto, banners_texto, vulns_texto, s["latencia"]
                ])
    except Exception as e:
        console.print(f"[red]Erro ao exportar CSV:[/red] {e}")
