"""
# src/cli/scanner_cli.py — CLI do scanner simples

## Descrição
Entry point do scanner de hosts com auditoria de segurança.
Única camada que interage com o usuário (input, print, export).

## Fluxo
1. auto_configurar() → obtém config do modo/ENV
2. Configura ENV vars para scan_service (antes do import)
3. Atualiza base NVD se necessário
4. Carrega tabela OUI
5. Solicita range de IPs ao usuário
6. run_batch_scan() → varre com lotes + cache + governança
7. run_cve_checks() → verifica CVEs nos banners coletados
8. Exibe relatório Rich no terminal
9. Oferta exportação CSV

Camada: cli
Dependências: src.core.batch_scanner, src.config.settings,
              src.infra.oui_loader, src.services.reporter,
              src.services.nvd_updater, src.cli.input_handler
"""

from __future__ import annotations

import os
from rich.console import Console

console = Console()


def main():
    """Ponto de entrada principal do verificador de hosts."""
    # 1) Configuração (deve ser feito ANTES de importar scan_service)
    from src.config.settings import auto_configurar
    config = auto_configurar()

    skip_cve = bool(config["skip_cve"])
    skip_nvd_update = bool(config["skip_nvd_update"])

    # 2) Configura ENV vars que scan_service lê no import (módulo-nível)
    os.environ["VH_MAX_SOCKETS"] = str(int(config["max_sockets"]))
    os.environ["VH_RESOLVE_HOSTNAME"] = "1" if config["resolve_hostname"] else "0"
    os.environ["VH_TCP_ONLY"] = "1" if config["tcp_only"] else "0"

    console.print(
        "[bold green]AutoConfig:[/bold green] "
        f"modo={config['mode']} | "
        f"hosts_threads={config['max_workers_hosts']} | "
        f"portas_threads={config['max_workers_portas']} | "
        f"timeout={config['timeout_socket']}s | "
        f"batch={config['batch_size']} | "
        f"max_sockets={config['max_sockets']} | "
        f"resolve_hostname={int(config['resolve_hostname'])} | "
        f"tcp_only={int(config['tcp_only'])} | "
        f"skip_cve={int(skip_cve)} | "
        f"skip_nvd_update={int(skip_nvd_update)} | "
        f"adaptive={int(config.get('adaptive', True))}"
    )

    # Imports tardios — todos dependem de scan_service estar configurado via ENV
    from src.core.batch_scanner import (
        needs_nvd_update, record_nvd_update,
        run_batch_scan, run_cve_checks,
    )
    from src.services.nvd_updater import atualizar_base_nvd
    from src.infra.oui_loader import carregar_tabela_oui
    from src.services.reporter import gerar_tabela, exportar_csv
    from src.cli.input_handler import solicitar_dados_input

    # 3) Atualização NVD
    if not skip_nvd_update and needs_nvd_update():
        console.print("\n[bold yellow]Atualizando base de vulnerabilidades da NVD...[/bold yellow]")
        try:
            atualizar_base_nvd()
            record_nvd_update()
            console.print("[green]Base NVD atualizada com sucesso.[/green]\n")
        except Exception as e:
            console.print(f"[red]Falha ao atualizar base NVD: {e}[/red]")
    else:
        console.print("\n[bold cyan]Pulando atualização da NVD (recente ou desabilitada).[/bold cyan]\n")

    # 4) Tabela OUI
    oui_table = carregar_tabela_oui()

    # 5) Input do usuário
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

    # 6) Varredura com governança adaptativa + cache
    results = run_batch_scan(config, ip_list, oui_table)

    # 7) Verificação de CVEs (centralizada, única passada)
    if not skip_cve:
        run_cve_checks(results)
    else:
        console.print("[yellow]skip_cve=1: verificação de CVEs desativada.[/yellow]")

    # 8) Relatório
    table = gerar_tabela(results)
    console.print("\n[bold cyan]Resumo Final:[/bold cyan]")
    console.print(table)

    # 9) Exportação CSV
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
