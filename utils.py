"""
# utils.py

## Descrição
Este módulo contém funções auxiliares de entrada e suporte para o sistema de verificação de hosts:
- Carregamento da tabela de fabricantes OUI
- Solicitação de dados do usuário (base de IP e faixa)
- Funções auxiliares reutilizáveis em outros módulos

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
    Carrega a tabela OUI a partir de um arquivo no formato Wireshark/Nmap.

    Retorna:
        dict: { 'XX:XX:XX': 'Nome do fabricante' }
    """
    fabricantes = {}

    if not os.path.exists(path):
        console.print(f"[red]Arquivo '{path}' não encontrado.[/red]")
        return fabricantes

    with open(path, encoding='utf-16') as f:
        for linha in f:
            if linha.strip().startswith('#') or not linha.strip():
                continue

            partes = linha.strip().split(None, 2)  # divide por qualquer espaço ou tab
            if len(partes) >= 2:
                prefixo = partes[0].upper().replace('-', ':').strip()
                prefixo = ":".join(prefixo.split(":")[:3])  # garante XX:XX:XX
                fabricante = partes[2].strip() if len(partes) >= 3 else partes[1].strip()
                fabricantes[prefixo] = fabricante

    return fabricantes



def solicitar_dados_input():
    """
    Solicita ao usuário os dados da rede a ser verificada.

    Retorna:
        tuple: (ip_base: str, ip_inicio: int, ip_fim: int)
    """
    console.print("==============================================", style="cyan")
    console.print(" Verificador de Hosts com Auditoria de Segurança", style="bold white")
    console.print("==============================================\n", style="cyan")

    while True:
        ip_base = input("Digite a base da rede (ex: 10.101.6): ").strip()
        if ip_base.count('.') == 2 and all(p.isdigit() for p in ip_base.split('.')):
            break
        console.print("[red]Base inválida. Use o formato: 10.101.X[/red]")

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
