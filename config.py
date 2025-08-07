"""
# config.py

## Descrição
Este módulo realiza a auto-configuração de desempenho com base nos recursos
do hardware local, como memória RAM e quantidade de núcleos de CPU.

É utilizado para ajustar automaticamente:
- Número ideal de threads para varredura de hosts
- Número de threads para varredura de portas TCP
- Tempo de timeout padrão para conexões socket

Este comportamento evita sobrecarregar a máquina em que o script for executado,
sendo especialmente útil em redes grandes ou computadores com hardware limitado.

## Autor
Luiz

## Dependências
- psutil: Para leitura de memória RAM disponível
- multiprocessing: Para detectar a quantidade de núcleos de CPU
"""

import psutil
import multiprocessing

def auto_configurar():
    """
    Ajusta automaticamente os parâmetros de varredura de acordo com os recursos do sistema.

    ### Lógica de ajuste:
    - Se o sistema tiver >= 8GB de RAM:
        - Usa até 1000 threads para hosts (limitado por CPU)
        - 50 threads para portas
    - Se o sistema tiver entre 4GB e 8GB:
        - Usa até (núcleos * 30) threads para hosts
        - 30 threads para portas
    - Se tiver menos de 4GB:
        - Limita a 100 threads para hosts e 10 para portas

    ### Retorno:
    dict: Um dicionário com as seguintes chaves:
        - `max_workers_hosts` (int): Número de threads para varredura de hosts
        - `max_workers_portas` (int): Número de threads para varredura de portas
        - `timeout_socket` (float): Tempo de espera padrão para conexões socket (em segundos)
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
