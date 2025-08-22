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

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
console = Console()

def _detectar_encoding(caminho: str) -> str:
    """Detecta BOM rápido: UTF-16 LE/BE, UTF-8; fallback utf-8."""
    try:
        with open(caminho, "rb") as fb:
            cab = fb.read(4)
        if cab.startswith(b"\xff\xfe"):
            return "utf-16-le"
        if cab.startswith(b"\xfe\xff"):
            return "utf-16-be"
        if cab.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
    except Exception:
        pass
    return "utf-8"  # fallback seguro


def carregar_tabela_oui(path='manuf'):
    """
    Carrega tabela OUI (Wireshark/Nmap) e indexa por:
    - FC52CE / FC:52:CE (3 bytes)
    - e também 4/5 bytes quando existirem no arquivo.
    """
    if not os.path.isabs(path):
        path = os.path.join(BASE_DIR, path)

    fabricantes = {}
    if not os.path.exists(path):
        console.print(f"[red]Arquivo '{path}' não encontrado.[/red]")
        return fabricantes

    enc = _detectar_encoding(path)

    try:
        with open(path, "r", encoding=enc, errors="strict") as f:
            for linha in f:
                s = linha.strip()
                if not s or s.startswith("#"):
                    continue

                # Divide por tab; formato Wireshark: "OUI<TAB>Short<TAB>Long ..."
                partes = s.split("\t")
                if len(partes) < 2:
                    # fallback: espaço(s) quando não houver tab
                    partes = s.split()
                    if len(partes) < 2:
                        continue

                raw = partes[0].upper().replace("-", ":")
                grupos = [g.strip() for g in raw.split(":") if g.strip()]
                if len(grupos) < 3:
                    continue

                nome = " ".join(partes[1:]).strip()
                # chaves de 3, 4 e 5 bytes
                for nbytes in (3, 4, 5):
                    if len(grupos) >= nbytes:
                        oui_colon = ":".join(grupos[:nbytes])               # FC:52:CE
                        oui_plain = oui_colon.replace(":", "")               # FC52CE
                        fabricantes[oui_colon] = nome
                        fabricantes[oui_plain] = nome
    except Exception as e:
        console.print(f"[red]Falha ao ler '{path}' ({enc}): {e}[/red]")

    if not fabricantes:
        console.print(f"[yellow]Aviso: tabela OUI vazia após ler {path} ({enc}).[/yellow]")
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
