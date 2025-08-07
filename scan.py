"""
# scan.py

## Descrição
Este módulo contém todas as funções responsáveis por escanear hosts e portas em uma rede local.

### Funcionalidades:
- Ping de IPs com extração de TTL e latência
- Resolução de hostname
- Obtenção de MAC address via ARP
- Identificação de fabricante via OUI
- Detecção do sistema operacional com base no TTL
- Teste de portas comuns (com banner grabbing)
- Verificação completa de um host, incluindo vulnerabilidades via CVE

## Autor
Luiz

## Dependências
- socket
- subprocess
- platform
- concurrent.futures
- re
- cve (interno)
"""

import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor
import re

from config import auto_configurar
from cve import verificar_vulnerabilidades_em_banners
from cve import carregar_base_local_cves


# ==== Listas de Portas ====

#: Portas comuns a serem escaneadas em cada host
PORTAS_COMUNS = [
    22, 23, 3389, 5900, 5985, 5986, 10000, 873, 111, 6000,
    80, 443, 8080, 8443, 8888, 5000, 5173, 4200, 7000, 8000, 8008,
    9000, 9443, 3000, 3001, 4000, 4001, 9090, 8086, 5601, 16101, 5353,
    1433, 1521, 3306, 5432, 27017, 6379, 11211, 9200, 9300, 2181, 9092,
    135, 137, 138, 139, 445,
    161, 162, 199, 3702, 5355,
    515, 631, 9100, 16101, 1900,
    88, 389, 636, 3268, 3269,
    20, 21, 69, 25, 587, 110, 995, 143, 993
]

#: Subconjunto de portas consideradas críticas ou sensíveis
PORTAS_CRITICAS = {
    23, 135, 137, 138, 139, 445,
    1433, 1521, 3306, 5432, 27017,
    3389, 5900, 6379, 11211, 9200,
    389, 21, 69, 5985, 5986
}


def ping_host(ip):
    """
    Executa um ping no IP informado e retorna status, TTL e latência estimada.

    Parâmetros:
        ip (str): Endereço IP.

    Retorna:
        (bool, int, float): (status, ttl, latência)
    """
    sistema = platform.system().lower()
    param = "-n" if sistema == "windows" else "-c"
    timeout_flag = "-w" if sistema == "windows" else "-W"

    try:
        output = subprocess.check_output(
            ["ping", param, "1", timeout_flag, "1", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )

        ttl_match = re.search(r'(ttl=|TTL=)(\d+)', output)
        ttl = int(ttl_match.group(2)) if ttl_match else -1

        time_match = re.search(r'(tempo|time)[=<]?\s*(\d+(?:\.\d+)?)\s*ms', output, re.IGNORECASE)
        latency = float(time_match.group(2)) if time_match else -1

        return True, ttl, latency
    except:
        return False, -1, -1


def detectar_so_por_ttl(ttl):
    """
    Detecta o sistema operacional estimado com base no valor TTL.

    Parâmetros:
        ttl (int): Time-to-Live do pacote.

    Retorna:
        str: SO estimado (colorido com tags do Rich).
    """
    if ttl <= 64:
        return "[green]Linux/Unix[/green]"
    elif ttl <= 128:
        return "[blue]Windows[/blue]"
    elif ttl <= 255:
        return "[magenta]Cisco/Outro[/magenta]"
    return "Desconhecido"


def get_mac(ip):
    """
    Obtém o endereço MAC do IP via comando ARP local.

    Parâmetros:
        ip (str): Endereço IP.

    Retorna:
        str: MAC formatado ou "MAC N/D"
    """
    try:
        output = subprocess.check_output(['arp', '-a', ip], text=True)
        for linha in output.splitlines():
            if ip in linha:
                partes = linha.split()
                for p in partes:
                    if '-' in p and len(p) == 17:
                        return p.upper().replace('-', ':')
    except:
        pass
    return "MAC N/D"


def resolve_hostname(ip):
    """
    Resolve o hostname associado ao IP.

    Parâmetros:
        ip (str): Endereço IP.

    Retorna:
        str: Hostname ou "Nome N/D"
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Nome N/D"


def banner_grabbing(ip, porta, timeout=1.5):
    """
    Coleta o banner da aplicação que responde em determinada porta.

    Parâmetros:
        ip (str): Endereço IP.
        porta (int): Número da porta.
        timeout (float): Tempo máximo de espera.

    Retorna:
        str: Banner limpo ou "-"
    """
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            banner = banner.replace("\n", " ").replace("\r", " ").replace(";", ",")
            return banner if banner else "-"
    except:
        return "-"


def testar_portas(ip, portas, max_workers, timeout):
    """
    Testa várias portas em paralelo em um IP e realiza banner grabbing nas abertas.

    Parâmetros:
        ip (str): IP alvo.
        portas (list): Lista de portas a testar.
        max_workers (int): Nº máximo de threads.
        timeout (float): Timeout de conexão.

    Retorna:
        list: Lista de tuplas (porta, banner)
    """
    def tentar(porta):
        try:
            with socket.create_connection((ip, porta), timeout=timeout):
                banner = banner_grabbing(ip, porta, timeout)
                return (porta, banner)
        except:
            return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        resultados = executor.map(tentar, portas)
    return [res for res in resultados if res]


def verificar_host(ip, fabricantes, max_workers_portas, timeout_socket, base_cves):
    """
    Realiza varredura completa de um host (ping, nome, MAC, portas, banners e CVEs).

    Parâmetros:
        ip (str): Endereço IP do alvo.
        fabricantes (dict): Dicionário de prefixos MAC → fabricante.
        max_workers_portas (int): Threads paralelas para scan de portas.
        timeout_socket (float): Timeout de conexão socket.
        base_cves (dict): Dicionário CVE {id: descrição}

    Retorna:
        dict: Dados do host analisado.
    """
    from scan import ping_host, resolve_hostname, get_mac, detectar_so_por_ttl, testar_portas, PORTAS_COMUNS

    status, ttl, latencia = ping_host(ip)

    # Host OFFLINE
    if not status:
        return {
            "ip": ip,
            "status": "OFFLINE",
            "nome": "-",
            "mac": "-",
            "fabricante": "-",
            "so": "-",
            "portas": [],
            "banners": [],
            "vulnerabilidades": [],
            "latencia": -1
        }

    # Host ONLINE
    nome = resolve_hostname(ip)
    mac = get_mac(ip)
    so = detectar_so_por_ttl(ttl)

    if mac != "MAC N/D":
        prefixo = ":".join(mac.split(":")[:3]).upper()
        fabricante = fabricantes.get(prefixo, "Fabricante N/D")
    else:
        fabricante = "Fabricante N/D"

    portas_banners = testar_portas(ip, PORTAS_COMUNS, max_workers_portas, timeout_socket)
    portas = [str(p) for p, _ in portas_banners]
    banners = [f"{p}:{b}" for p, b in portas_banners]

    vulnerabilidades = verificar_vulnerabilidades_em_banners([b for _, b in portas_banners], base_cves)

    return {
        "ip": ip,
        "status": "ONLINE",
        "nome": nome,
        "mac": mac,
        "fabricante": fabricante,
        "so": so,
        "portas": portas,
        "banners": banners,
        "vulnerabilidades": vulnerabilidades,
        "latencia": latencia
    }
