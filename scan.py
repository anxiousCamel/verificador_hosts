"""
# scan.py

## Descrição
Este módulo contém todas as funções responsáveis por escanear hosts e portas:
- Ping de IPs
- Resolução de hostname
- Obtenção de MAC Address
- Identificação de fabricante via OUI
- Detectar sistema operacional pelo TTL
- Teste de portas comuns (com banner grabbing)
- Verificação completa de um host (incluindo vulnerabilidades)


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

PORTAS_CRITICAS = {
    23, 135, 137, 138, 139, 445,
    1433, 1521, 3306, 5432, 27017,
    3389, 5900, 6379, 11211, 9200,
    389, 21, 69, 5985, 5986
}

def ping_host(ip):
    sistema = platform.system().lower()
    param = "-n" if sistema == "windows" else "-c"
    timeout_flag = "-w" if sistema == "windows" else "-W"
    
    try:
        output = subprocess.check_output(
            ["ping", param, "1", timeout_flag, "1", ip],
            stderr=subprocess.DEVNULL,
            universal_newlines=True
        )

        # TTL é comum para todos
        ttl_match = re.search(r'(ttl=|TTL=)(\d+)', output)
        ttl = int(ttl_match.group(2)) if ttl_match else -1

        # Regex multilíngue para capturar latência:
        #   - Linux: "time=1.23 ms"
        #   - Windows EN: "time=1ms"
        #   - Windows PT-BR: "tempo=1ms"
        time_match = re.search(r'(tempo|time)[=<]?\s*(\d+(?:\.\d+)?)\s*ms', output, re.IGNORECASE)
        latency = float(time_match.group(2)) if time_match else -1

        return True, ttl, latency
    except:
        return False, -1, -1


def detectar_so_por_ttl(ttl):
    if ttl <= 64:
        return "[green]Linux/Unix[/green]"
    elif ttl <= 128:
        return "[blue]Windows[/blue]"
    elif ttl <= 255:
        return "[magenta]Cisco/Outro[/magenta]"
    return "Desconhecido"

def get_mac(ip):
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
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Nome N/D"

def banner_grabbing(ip, porta, timeout=1.5):
    try:
        with socket.create_connection((ip, porta), timeout=timeout) as s:
            s.settimeout(timeout)
            banner = s.recv(1024).decode(errors="ignore").strip()
            banner = banner.replace("\n", " ").replace("\r", " ").replace(";", ",")
            return banner if banner else "-"
    except:
        return "-"

def testar_portas(ip, portas, max_workers, timeout):
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


def verificar_host(ip, fabricantes, max_workers_portas, timeout_socket):
    """
    Realiza varredura completa de um host.

    Parâmetros:
        ip (str): Endereço IP.
        fabricantes (dict): Dicionário OUI.
        max_workers_portas (int): Nº de threads para escanear portas.
        timeout_socket (float): Timeout de conexão em segundos.

    Retorna:
        dict: Dicionário contendo os dados do host
    """
    from scan import ping_host, resolve_hostname, get_mac, detectar_so_por_ttl, testar_portas, PORTAS_COMUNS



    status, ttl, latencia = ping_host(ip)
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

    nome = resolve_hostname(ip)
    mac = get_mac(ip)
    so = detectar_so_por_ttl(ttl)
    if mac != "MAC N/D":
        prefixo = ":".join(mac.split(":")[:3]).upper()  # Ex: FC:52:CE
        fabricante = fabricantes.get(prefixo, "Fabricante N/D")
    else:
        fabricante = "Fabricante N/D"
    portas_banners = testar_portas(ip, PORTAS_COMUNS, max_workers_portas, timeout_socket)

    portas = [str(p) for p, _ in portas_banners]
    banners = [f"{p}:{b}" for p, b in portas_banners]
    
    vulnerabilidades = verificar_vulnerabilidades_em_banners([b for _, b in portas_banners])

    if mac != "MAC N/D":
        prefixo = ":".join(mac.split(":")[:3]).upper().strip()
        fabricante = fabricantes.get(prefixo, "Fabricante N/D")
    else:
        fabricante = "Fabricante N/D"
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