"""
# config.py

## Descrição
Este módulo realiza a auto-configuração de desempenho com base nos recursos
do hardware (RAM e núcleos de CPU). Ele determina:
- Número ideal de threads para varredura de hosts
- Número de threads para varredura de portas
- Tempo padrão de timeout para conexões

## Autor
Luiz

## Dependências
- psutil
- multiprocessing
"""

import psutil
import multiprocessing


def auto_configurar():
    """
    Ajusta automaticamente a configuração do scanner com base nos recursos do sistema.

    - Hosts: aumenta o número de threads proporcionalmente à RAM/CPU.
    - Portas: limita o número de conexões simultâneas dependendo da memória.
    - Timeout: define o tempo de espera padrão para conexões socket.

    ### Retorna:
    dict: Contendo as chaves:
        - max_workers_hosts (int): Nº de threads para verificação de hosts.
        - max_workers_portas (int): Nº de threads para escaneamento de portas.
        - timeout_socket (float): Tempo de timeout para conexões (segundos).
    """
    total_ram_gb = psutil.virtual_memory().total / (1024 ** 3)
    cpus = multiprocessing.cpu_count()

    if total_ram_gb >= 8:
        max_workers_hosts = min(1000, cpus * 50)
        max_workers_portas = 50
    elif total_ram_gb >= 4:
        max_workers_hosts = cpus * 30
        max_workers_portas = 30
    else:
        max_workers_hosts = 100
        max_workers_portas = 10

    return {
        "max_workers_hosts": max_workers_hosts,
        "max_workers_portas": max_workers_portas,
        "timeout_socket": 5.0
    }
