"""
# utils.py — Funções utilitárias do Verificador de Hosts

## Descrição
Funções auxiliares reutilizáveis:
- Carregamento da tabela OUI (fabricantes por MAC, formato Wireshark/Nmap)
- Detecção de encoding de arquivos (UTF-8, UTF-16 LE/BE)
- Validação interativa de entrada de rede (base IP, faixa)

## Autor
Luiz
"""

import os
from rich.console import Console

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
console = Console()


# ============================
# Detecção de encoding
# ============================

def _detect_encoding(filepath: str) -> str:
    """
    Detecta encoding via BOM (Byte Order Mark).

    Suporta UTF-16 LE, UTF-16 BE e UTF-8 com BOM. Fallback para UTF-8.

    Args:
        filepath: Caminho do arquivo.

    Returns:
        String de encoding compatível com open().
    """
    try:
        with open(filepath, "rb") as f:
            header = f.read(4)
        if header.startswith(b"\xff\xfe"):
            return "utf-16-le"
        if header.startswith(b"\xfe\xff"):
            return "utf-16-be"
        if header.startswith(b"\xef\xbb\xbf"):
            return "utf-8-sig"
    except Exception:
        pass
    return "utf-8"


# ============================
# Tabela OUI (fabricantes)
# ============================

def carregar_tabela_oui(path: str = "manuf") -> dict:
    """
    Carrega tabela OUI no formato Wireshark/Nmap.

    O arquivo contém mapeamentos de prefixos MAC (OUI) para nomes de fabricantes.
    Formato: "OUI<TAB>Short<TAB>Long description"

    Indexa por múltiplas representações para lookup flexível:
    - Com dois-pontos: "FC:52:CE"
    - Sem separador: "FC52CE"
    - Para OUIs de 3, 4 e 5 bytes (suporte a MA-L, MA-M, MA-S do IEEE)

    Args:
        path: Caminho do arquivo OUI (relativo ao diretório do módulo).

    Returns:
        Dicionário {oui_string: nome_fabricante}.
    """
    if not os.path.isabs(path):
        path = os.path.join(_BASE_DIR, path)

    oui_table: dict = {}
    if not os.path.exists(path):
        console.print(f"[red]Arquivo '{path}' não encontrado.[/red]")
        return oui_table

    encoding = _detect_encoding(path)

    try:
        with open(path, "r", encoding=encoding, errors="strict") as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue

                # Parse: OUI<TAB>Short<TAB>Long...
                parts = stripped.split("\t")
                if len(parts) < 2:
                    parts = stripped.split()
                    if len(parts) < 2:
                        continue

                raw_oui = parts[0].upper().replace("-", ":")
                groups = [g.strip() for g in raw_oui.split(":") if g.strip()]
                if len(groups) < 3:
                    continue

                name = " ".join(parts[1:]).strip()

                # Indexa OUI de 3, 4 e 5 bytes (duas representações cada)
                for num_bytes in (3, 4, 5):
                    if len(groups) >= num_bytes:
                        with_colons = ":".join(groups[:num_bytes])
                        without_colons = with_colons.replace(":", "")
                        oui_table[with_colons] = name
                        oui_table[without_colons] = name

    except Exception as e:
        console.print(f"[red]Falha ao ler '{path}' ({encoding}): {e}[/red]")

    if not oui_table:
        console.print(f"[yellow]Aviso: tabela OUI vazia após ler {path}.[/yellow]")

    return oui_table


# ============================
# Input interativo
# ============================

def solicitar_dados_input() -> tuple:
    """
    Solicita dados da rede ao usuário via terminal.

    Pede:
    - Base da rede (ex: "10.101.6")
    - IP inicial e final da faixa (1-254)

    Valida formato e intervalo antes de retornar.

    Returns:
        Tupla (ip_base: str, ip_inicio: int, ip_fim: int).

    Raises:
        KeyboardInterrupt: Se o usuário cancelar (Ctrl+C).
    """
    console.print("==============================================", style="cyan")
    console.print(" Verificador de Hosts com Auditoria de Segurança", style="bold white")
    console.print("==============================================\n", style="cyan")

    # Base da rede
    while True:
        ip_base = input("Digite a base da rede (ex: 10.101.6): ").strip()
        octets = ip_base.split(".")
        if len(octets) == 3 and all(o.isdigit() for o in octets):
            break
        console.print("[red]Base inválida. Use o formato: X.X.X (ex: 10.101.6)[/red]")

    # Faixa de IPs
    while True:
        try:
            start = int(input("IP inicial (ex: 1): "))
            end = int(input("IP final (ex: 254): "))
            if 0 < start <= 254 and 0 < end <= 254 and start <= end:
                break
            console.print("[red]Valores fora do intervalo válido (1 a 254).[/red]")
        except ValueError:
            console.print("[red]Digite números válidos.[/red]")

    return ip_base, start, end
