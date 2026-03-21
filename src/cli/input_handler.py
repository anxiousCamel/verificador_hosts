"""
# src/cli/input_handler.py — Entrada interativa de dados de rede

## Descrição
Solicita e valida dados de rede ao usuário via terminal.
Responsabilidade única: I/O com o usuário para definição do alvo.

Camada: cli (sem dependências de projeto além de rich)
"""

from rich.console import Console

console = Console()


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
