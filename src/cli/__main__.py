"""
Dispatcher: python -m src.cli

Uso:
    python -m src.cli            → scanner simples (padrão)
    python -m src.cli --pentest  → pipeline de pentest
"""

import sys
from src.cli.scanner_cli import main as scanner_main
from src.cli.pentest_cli import main as pentest_main

if "--pentest" in sys.argv:
    pentest_main()
else:
    scanner_main()
