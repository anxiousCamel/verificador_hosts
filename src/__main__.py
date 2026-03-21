"""
Entry point padrão: python -m src

Equivale a python -m src.cli (scanner simples).
Para o pipeline de pentest: python -m src.cli --pentest
"""

from src.cli.scanner_cli import main

main()
