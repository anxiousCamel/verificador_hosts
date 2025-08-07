"""
Módulo principal de execução.
Executa a auditoria de rede com base na varredura por IPs, exibe os dados
e permite exportar o resultado em CSV.

Este módulo é responsável apenas por orquestrar as chamadas dos módulos:
- config.py (auto-configuração)
- scan.py (varredura)
- utils.py (utilitários e entrada)
- relatorio.py (visualização/exportação)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from rich.console import Console
from datetime import datetime, timedelta
import os

from config import auto_configurar
from utils import solicitar_dados_input, carregar_tabela_oui
from scan import verificar_host
from relatorio import gerar_tabela, exportar_csv
from cve import carregar_base_local_cves

base_cves = carregar_base_local_cves()
from atualizar_nvd import atualizar_base_nvd

CAMINHO_NVD = "nvd_data"
CAMINHO_REGISTRO_ATUALIZACAO = os.path.join(CAMINHO_NVD, "ultima_atualizacao.txt")
INTERVALO_DIAS_ATUALIZACAO = 7

console = Console()

def precisa_atualizar_nvd():
    try:
        if not os.path.exists(CAMINHO_REGISTRO_ATUALIZACAO):
            return True

        with open(CAMINHO_REGISTRO_ATUALIZACAO, "r") as f:
            ultima_str = f.read().strip()
            ultima_data = datetime.strptime(ultima_str, "%Y-%m-%d")

        return datetime.now() - ultima_data > timedelta(days=INTERVALO_DIAS_ATUALIZACAO)
    except:
        return True

def registrar_data_atualizacao():
    os.makedirs(CAMINHO_NVD, exist_ok=True)
    with open(CAMINHO_REGISTRO_ATUALIZACAO, "w") as f:
        f.write(datetime.now().strftime("%Y-%m-%d"))

def main():
    # Atualiza CVEs automaticamente se necessário
    if precisa_atualizar_nvd():
        console.print("\n[bold yellow]Atualizando base de vulnerabilidades da NVD...[/bold yellow]")
        print("[cyan]Verificando atualizações da base CVE...[/cyan]")
        atualizar_base_nvd()
        registrar_data_atualizacao()
        console.print("[green]Base NVD atualizada com sucesso.[/green]\n")
    else:
        console.print("\n[bold cyan]Base NVD atualizada recentemente. Pulando atualização.[/bold cyan]\n")

    config = auto_configurar()

    console.print(f"\n[bold green]AutoConfig:[/bold green] max_threads={config['max_workers_hosts']} | "
                    f"portas_threads={config['max_workers_portas']} | timeout={config['timeout_socket']}s\n")

    fabricantes = carregar_tabela_oui()
    
    ip_base, inicio, fim = solicitar_dados_input()
    lista_ips = [f"{ip_base}.{i}" for i in range(inicio, fim + 1)]

    status_dict = {}
    with ThreadPoolExecutor(max_workers=config["max_workers_hosts"]) as executor:
        tarefas = {
            executor.submit(
                verificar_host,
                ip,
                fabricantes,
                config["max_workers_portas"],
                config["timeout_socket"],
                base_cves
            ): ip for ip in lista_ips
        }

        for future in tqdm(as_completed(tarefas), total=len(tarefas), desc="Verificando Hosts", ncols=100):
            resultado = future.result()
            status_dict[resultado["ip"]] = resultado

    tabela = gerar_tabela(status_dict)
    console.print("\n[bold cyan]Resumo Final:[/bold cyan]")
    console.print(tabela)

    salvar = input("\nDeseja exportar o resultado para CSV? (s/n): ").strip().lower()
    if salvar == "s":
        caminho = input("Caminho para salvar (padrão: auditoria_hosts.csv): ").strip() or "auditoria_hosts.csv"
        exportar_csv(status_dict, caminho)
        console.print(f"[green]Exportado para {caminho}[/green]")

    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    main()