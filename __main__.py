"""
Módulo principal de execução.

Este módulo orquestra a execução completa da auditoria de rede:
- Atualiza a base de CVEs da NVD automaticamente, se necessário.
- Solicita a faixa de IPs a ser verificada.
- Executa a varredura de rede com análise de portas e CVEs.
- Exibe os dados no terminal usando `rich`.
- Oferece exportação do relatório em CSV.

Módulos utilizados:
- config.py      => Autoconfiguração (nº de threads, timeout, etc)
- scan.py        => Varredura de IPs e portas
- utils.py       => Funções auxiliares e entrada de dados
- relatorio.py   => Exibição e exportação dos dados
- cve.py         => Carregamento dos arquivos CVE
- atualizar_nvd.py => Atualização automática da base CVE da NVD
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from rich.console import Console
from datetime import datetime, timedelta
import os

# Importações dos módulos internos
from config import auto_configurar
from utils import solicitar_dados_input, carregar_tabela_oui
from scan import verificar_host
from relatorio import gerar_tabela, exportar_csv
from atualizar_nvd import atualizar_base_nvd
from cve import carregar_base_local_cves

# Configurações da base NVD
CAMINHO_NVD = "nvd_data"
CAMINHO_REGISTRO_ATUALIZACAO = os.path.join(CAMINHO_NVD, "ultima_atualizacao.txt")
INTERVALO_DIAS_ATUALIZACAO = 7

console = Console()

def precisa_atualizar_nvd():
    """
    Verifica se a base local da NVD precisa ser atualizada com base na data do último check.
    Retorna True se passou o intervalo definido ou se o arquivo de verificação não existe.
    """
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
    """
    Registra a data da última atualização da base NVD em arquivo.
    """
    os.makedirs(CAMINHO_NVD, exist_ok=True)
    with open(CAMINHO_REGISTRO_ATUALIZACAO, "w") as f:
        f.write(datetime.now().strftime("%Y-%m-%d"))

def main():
    """
    Ponto de entrada principal da aplicação:
    - Atualiza base NVD se necessário
    - Solicita faixa de IP
    - Varre os hosts e portas
    - Identifica vulnerabilidades
    - Exibe e exporta resultado
    """
    # Atualização automática da base NVD
    if precisa_atualizar_nvd():
        console.print("\n[bold yellow]Atualizando base de vulnerabilidades da NVD...[/bold yellow]")
        print("[cyan]Verificando atualizações da base CVE...[/cyan]")
        atualizar_base_nvd()
        registrar_data_atualizacao()
        console.print("[green]Base NVD atualizada com sucesso.[/green]\n")
    else:
        console.print("\n[bold cyan]Base NVD atualizada recentemente. Pulando atualização.[/bold cyan]\n")

    # Importante: carregar os CVEs somente após a atualização!
    base_cves = carregar_base_local_cves()

    # Carregar configurações automáticas
    config = auto_configurar()
    console.print(f"\n[bold green]AutoConfig:[/bold green] max_threads={config['max_workers_hosts']} | "
                    f"portas_threads={config['max_workers_portas']} | timeout={config['timeout_socket']}s\n")

    # Carregar tabela OUI de fabricantes
    fabricantes = carregar_tabela_oui()

    # Solicita IP base e intervalo
    ip_base, inicio, fim = solicitar_dados_input()
    lista_ips = [f"{ip_base}.{i}" for i in range(inicio, fim + 1)]

    # Execução da varredura paralela de hosts
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

    # Geração e exibição do relatório final
    tabela = gerar_tabela(status_dict)
    console.print("\n[bold cyan]Resumo Final:[/bold cyan]")
    console.print(tabela)

    # Exportação para CSV
    salvar = input("\nDeseja exportar o resultado para CSV? (s/n): ").strip().lower()
    if salvar == "s":
        caminho = input("Caminho para salvar (padrão: auditoria_hosts.csv): ").strip() or "auditoria_hosts.csv"
        exportar_csv(status_dict, caminho)
        console.print(f"[green]Exportado para {caminho}[/green]")

    input("\nPressione Enter para sair...")

if __name__ == "__main__":
    main()
