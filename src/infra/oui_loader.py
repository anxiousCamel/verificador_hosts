"""
# src/infra/oui_loader.py — Carregamento da tabela OUI (fabricantes por MAC)

## Descrição
Carrega a tabela OUI no formato Wireshark/Nmap para lookup de fabricantes
a partir de endereços MAC.

Camada: infra (sem dependências de projeto)
"""

import os
from rich.console import Console

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))
console = Console()


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
        path: Caminho do arquivo OUI. Relativo à raiz do projeto se não absoluto.

    Returns:
        Dicionário {oui_string: nome_fabricante}.
    """
    # Resolve relativo à raiz do projeto (dois níveis acima de src/infra/)
    if not os.path.isabs(path):
        project_root = os.path.dirname(os.path.dirname(_BASE_DIR))
        path = os.path.join(project_root, path)

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
