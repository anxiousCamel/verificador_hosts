"""
# utils.py

## Descrição
Este módulo contém funções auxiliares utilizadas pelo sistema de verificação de hosts.

### Funcionalidades:
- Carregamento da tabela de fabricantes OUI (formato Nmap/Wireshark)
- Solicitação interativa de dados da rede (base e faixa IP)
- Funções reutilizáveis que evitam duplicação de lógica

## Autor
Luiz

## Dependências
- os
- rich.console
"""

import os
from rich.console import Console

console = Console()


def carregar_tabela_oui(path='manuf'):
    """
    Carrega a tabela OUI (Wireshark/Nmap) e indexa por duas chaves:
    - 'FC52CE' (sem separadores)
    - 'FC:52:CE' (com dois-pontos)
    """
    fabricantes = {}

    if not os.path.exists(path):
        console.print(f"[red]Arquivo '{path}' não encontrado.[/red]")
        return fabricantes

    # Tente latin-1; se falhar, caia para utf-8
    for enc in ("latin-1", "utf-8", "utf-16"):
        try:
            with open(path, encoding=enc, errors="ignore") as f:
                for linha in f:
                    if linha.strip().startswith('#') or not linha.strip():
                        continue

                    partes = linha.strip().split()
                    if len(partes) < 2:
                        continue

                    # primeira coluna é o prefixo (pode vir com '-' ou ':')
                    raw = partes[0].upper()
                    raw = raw.replace('-', ':').strip()
                    # normaliza
                    oui_colon = ":".join(raw.split(":")[:3])                  # FC:52:CE
                    oui_plain = oui_colon.replace(":", "")                    # FC52CE
                    fabricante = " ".join(partes[1:]).strip()

                    if oui_plain:
                        fabricantes[oui_plain] = fabricante
                    if oui_colon:
                        fabricantes[oui_colon] = fabricante
            break
        except Exception:
            continue

    return fabricantes



def solicitar_dados_input():
    """
    Solicita os dados de entrada ao usuário no terminal:
    - Base de rede no formato 10.101.X
    - Faixa de IPs (início e fim)

    Valida as entradas antes de prosseguir.

    Retorna:
        tuple: (ip_base: str, ip_inicio: int, ip_fim: int)

    Exemplo de retorno:
        ("10.101.6", 1, 150)
    """
    console.print("==============================================", style="cyan")
    console.print(" Verificador de Hosts com Auditoria de Segurança", style="bold white")
    console.print("==============================================\n", style="cyan")

    # Solicita a base da rede
    while True:
        ip_base = input("Digite a base da rede (ex: 10.101.6): ").strip()
        if ip_base.count('.') == 2 and all(p.isdigit() for p in ip_base.split('.')):
            break
        console.print("[red]Base inválida. Use o formato: 10.101.X[/red]")

    # Solicita IP inicial e final
    while True:
        try:
            inicio = int(input("IP inicial (ex: 1): "))
            fim = int(input("IP final (ex: 254): "))
            if 0 < inicio <= 254 and 0 < fim <= 254 and inicio <= fim:
                break
            else:
                console.print("[red]Valores fora do intervalo válido (1 a 254).[/red]")
        except ValueError:
            console.print("[red]Digite números válidos para os IPs.[/red]")

    return ip_base, inicio, fim
