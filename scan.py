"""
# scan.py

## Descrição
Scanner de hosts e portas com:
- Ping + TTL + latência
- Hostname (opcional por ENV)
- MAC por ARP e fabricante (via dicionário `fabricantes`)
- Detecção de SO via TTL
- Portscan com banner grabbing usando **probes por protocolo**
- Limite global de sockets (semáforo) para não travar a máquina
- Montagem do dicionário final do host (compatível com __main__.py/relatorio.py)

Cada função faz UMA coisa. Comentários em Markdown/Doxygen.

## Autor
Luiz
"""

from __future__ import annotations

import os
import re
import ssl
import socket
import platform
import subprocess
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
import threading

# ============================
# Configs por ENV
# ============================

MAX_SOCKETS = int(os.getenv("VH_MAX_SOCKETS", "256"))   # limite global de sockets simultâneos
RESOLVE_HOSTNAME = os.getenv("VH_RESOLVE_HOSTNAME", "1") == "1"

SOCKET_SEM = threading.Semaphore(MAX_SOCKETS)


@contextmanager
def open_conn(ip: str, porta: int, timeout: float):
    """
    Context manager para abrir conexão respeitando o limite global de sockets.
    Garante liberação do semáforo e fechamento do socket.
    """
    SOCKET_SEM.acquire()
    s = None
    try:
        s = socket.create_connection((ip, porta), timeout=timeout)
        yield s
    finally:
        try:
            if s:
                s.close()
        finally:
            SOCKET_SEM.release()


# ============================
# Portas (blocos lógicos)
# ============================

# Portas críticas (para destaque no relatório, se desejar)
PORTAS_CRITICAS = [
    # Administração remota sensível
    22,      # SSH
    23,      # Telnet
    3389,    # RDP
    5900,    # VNC
    5985, 5986,  # WinRM
    # Compartilhamento e RPC
    135, 137, 138, 139, 445,
]

# Portas comuns (varredura padrão)
PORTAS_COMUNS = sorted(set([
    # Administração
    22, 23, 3389, 5900, 5985, 5986, 10000,
    # Web
    80, 443, 8080, 8443, 8888, 8000,
    # Bancos de dados
    1433, 1521, 3306, 5432,
    # Compartilhamento de arquivos e RPC
    135, 137, 138, 139, 445,
    # Email
    25, 465, 587, 110, 995, 143, 993,
    # Infraestrutura e diversos
    3000, 3001, 4000, 4001, 6379, 11211, 27017,
    # Impressão e dispositivos
    515, 631, 9100,
]))


# ============================
# Probes por protocolo
# ============================

SERVICE_PROBES: Dict[int, bytes] = {
    # HTTP (HEAD simples)
    80:   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    # HTTPS/TLS direto (tratado à parte quando 443)
    443:  b"",
    # SSH: banner vem do servidor
    22:   b"\r\n",
    # SMTP
    25:   b"EHLO example.com\r\n",
    587:  b"EHLO example.com\r\n",
    465:  b"",  # SMTPS (TLS direto)
    # POP3
    110:  b"USER test\r\n",
    995:  b"",  # POP3S (TLS direto)
    # IMAP
    143:  b". CAPABILITY\r\n",
    993:  b"",  # IMAPS (TLS direto)
    # FTP
    21:   b"FEAT\r\n",
    990:  b"",  # FTPS (TLS direto)
}


# ============================
# Helpers (uma função = uma coisa)
# ============================

def _clean_banner(s: str) -> str:
    """Normaliza banner para uma linha curta."""
    if not s:
        return "-"
    s = s.replace("\r", " ").replace("\n", " ").strip()
    s = s.replace(";", ",")
    return s if s else "-"


def _recv_small(sock: socket.socket, chunk_size: int = 2048) -> bytes:
    """Recebe um bloco pequeno sem bloquear por muito tempo."""
    try:
        return sock.recv(chunk_size)
    except Exception:
        return b""


def _banner_https(ip: str, timeout: float) -> str:
    """Handshake TLS + tentativa de HEAD em :443."""
    try:
        with open_conn(ip, 443, timeout) as raw:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                tls.settimeout(timeout)
                try:
                    req = b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                    tls.sendall(req)
                    data = _recv_small(tls)
                    return _clean_banner(data.decode(errors="ignore"))
                except Exception:
                    data = _recv_small(tls)
                    return _clean_banner(data.decode(errors="ignore"))
    except Exception:
        return "-"


def banner_grabbing(ip: str, porta: int, timeout: float = 2.5) -> str:
    """Obtém banner usando probes específicas por porta (com limite global de sockets)."""
    if porta in (443, 465, 993, 995, 990):
        if porta == 443:
            return _banner_https(ip, timeout)
        try:
            with open_conn(ip, porta, timeout) as raw:
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                    tls.settimeout(timeout)
                    data = _recv_small(tls)
                    return _clean_banner(data.decode(errors="ignore"))
        except Exception:
            return "-"

    probe = SERVICE_PROBES.get(porta)
    try:
        with open_conn(ip, porta, timeout) as s:
            s.settimeout(timeout)
            if probe:
                try:
                    s.sendall(probe)
                except Exception:
                    pass
            data = _recv_small(s)
            return _clean_banner(data.decode(errors="ignore"))
    except Exception:
        return "-"


def re_search_i(pattern: str, text: str) -> Optional[str]:
    """Regex case-insensitive, retorna primeiro grupo ou None."""
    m = re.search(pattern, text or "", flags=re.IGNORECASE)
    return m.group(1) if m else None


def parse_http_server(banner: str) -> str:
    """Extrai 'Server: ...' se existir (útil para casar produto/versão)."""
    if not banner or banner == "-":
        return banner
    v = re_search_i(r"\bserver:\s*([^\r\n]+)", banner)
    return _clean_banner(f"Server: {v}") if v else banner


# ============================
# Ping / TTL / Latência / Hostname / MAC / SO
# ============================

def _ping_args(ip: str) -> List[str]:
    """Monta args do ping conforme SO."""
    if platform.system().lower().startswith("win"):
        return ["ping", "-n", "1", "-w", "1200", ip]
    else:
        return ["ping", "-c", "1", "-W", "1", ip]


def ping_host(ip: str) -> Tuple[bool, int, float]:
    """
    Executa 1 ping e tenta extrair TTL e latência (ms).
    Retorna (online, ttl, lat_ms) — ttl=-1/lat=-1 se não obtido.
    """
    ttl, lat = -1, -1.0
    try:
        p = subprocess.run(_ping_args(ip), capture_output=True, text=True, timeout=3)
        out = p.stdout + p.stderr
        online = p.returncode == 0 or ("bytes=" in out.lower() or "ttl=" in out.lower())
        if not online:
            return False, -1, -1.0

        # Latência
        mlat = re_search_i(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", out) or \
               re_search_i(r"tempo[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", out)
        if mlat:
            lat = float(mlat)

        # TTL
        mttl = re_search_i(r"ttl[=\s]\s*([0-9]+)", out)
        if mttl:
            ttl = int(mttl)

        return True, ttl, lat
    except Exception:
        return False, -1, -1.0


def resolver_hostname(ip: str) -> str:
    """Resolve hostname via DNS inverso (best-effort)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/D"


def obter_mac_via_arp(ip: str) -> str:
    """
    Tenta extrair MAC da tabela ARP.
    Windows: `arp -a`
    Linux:   `ip neigh` (fallback `arp -n`)
    """
    try:
        if platform.system().lower().startswith("win"):
            p = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=2)
            out = p.stdout
            mm = re.search(rf"{re.escape(ip)}\s+([0-9a-fA-F\-\:]+)", out)
            if mm:
                mac = mm.group(1).replace("-", ":").lower()
                return mac
        else:
            p = subprocess.run(["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=2)
            out = p.stdout
            mm = re.search(r"lladdr\s+([0-9a-fA-F:]{17})", out)
            if mm:
                return mm.group(1).lower()
            # fallback
            p = subprocess.run(["arp", "-n", ip], capture_output=True, text=True, timeout=2)
            out = p.stdout
            mm = re.search(r"([0-9a-fA-F:]{17})", out)
            if mm:
                return mm.group(1).lower()
    except Exception:
        pass
    return "N/D"


def detectar_so_por_ttl(ttl: int) -> str:
    """
    Heurística simples:
    - ~64  => Linux/Unix-like
    - ~128 => Windows
    - ~255 => Cisco/NX-OS/alguns appliances
    """
    if ttl < 0:
        return "N/D"
    if ttl <= 70:
        return "Linux/Unix"
    if ttl <= 140:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Appliance"
    return "Desconhecido"


# ============================
# Portscan paralelo (usa probes)
# ============================

def _testar_porta(ip: str, porta: int, timeout: float) -> Tuple[int, str]:
    """Conecta e coleta banner se aberto. Retorna (porta, banner|'-')."""
    # Testa apenas a conexão (controlada)
    try:
        with open_conn(ip, porta, timeout):
            pass  # conectou -> aberta
    except Exception:
        return (porta, "-")

    # Coleta banner (nova conexão controlada)
    banner = banner_grabbing(ip, porta, timeout=timeout)
    if porta in (80, 8080, 8000, 8888, 8443, 443):
        banner = parse_http_server(banner)
    return (porta, banner if banner else "-")


def testar_portas(ip: str, portas: List[int], timeout: float = 2.5, workers: int = 64) -> List[str]:
    """
    Retorna lista **somente** das portas abertas no formato "porta:banner".
    """
    resultados: List[str] = []
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futuros = [ex.submit(_testar_porta, ip, p, timeout) for p in portas]
        for fut in as_completed(futuros):
            porta, banner = fut.result()
            if banner and banner != "-":
                resultados.append(f"{porta}:{banner}")
    # ordena por porta
    try:
        resultados.sort(key=lambda x: int(x.split(":", 1)[0]))
    except Exception:
        resultados.sort()
    return resultados


# ============================
# Função principal por host (chamada pelo __main__.py)
# ============================

import re

def _fabricante_por_mac(mac: str, fabricantes: Dict[str, str]) -> str:
    """Retorna fabricante tentando OUI de 3, 4 e 5 bytes (plain e com ':')."""
    if not mac or mac in ("N/D", "MAC N/D", "-"):
        return "N/D"
    hexs = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()   # ex.: 80854495F30E
    if len(hexs) < 6:
        return "N/D"
    keys = []
    for n in (6, 8, 10):  # 3,4,5 bytes
        if len(hexs) >= n:
            plain = hexs[:n]
            colon = ':'.join(plain[i:i+2] for i in range(0, n, 2))
            if plain in fabricantes: return fabricantes[plain]
            if colon in fabricantes: return fabricantes[colon]
    return 'N/D'



def verificar_host(
    ip: str,
    fabricantes: Dict[str, str],
    max_workers_portas: int,
    timeout_socket: float,
    base_cves
) -> Dict[str, object]:
    """
    ## verificar_host
    - Ping + TTL + latência
    - Hostname (opcional por ENV)
    - MAC e fabricante
    - SO (por TTL)
    - Portscan + banners
    - Vulnerabilidades (usa cve.verificar_vulnerabilidades_em_banners)

    Retorno (campos compatíveis com relatorio.py):
    {
        "ip": str,
        "status": "ONLINE"/"OFFLINE",
        "nome": str,
        "mac": str,
        "fabricante": str,
        "so": str,
        "portas": List[str],
        "banners": List[str],
        "vulnerabilidades": List[str],
        "latencia": float
    }
    """
    online, ttl, latencia = ping_host(ip)
    if not online:
        return {
            "ip": ip,
            "status": "OFFLINE",
            "nome": "N/D",
            "mac": "N/D",
            "fabricante": "N/D",
            "so": "N/D",
            "portas": [],
            "banners": [],
            "vulnerabilidades": [],
            "latencia": -1.0,
        }

    nome = resolver_hostname(ip) if RESOLVE_HOSTNAME else "N/D"
    mac = obter_mac_via_arp(ip)
    fabricante = _fabricante_por_mac(mac, fabricantes)
    so = detectar_so_por_ttl(ttl)

    # Portscan
    banners_abertas = testar_portas(
        ip,
        PORTAS_COMUNS,
        timeout=float(timeout_socket),
        workers=int(max_workers_portas),
    )
    portas = [b.split(":", 1)[0] for b in banners_abertas]
    banners = banners_abertas[:]  # já no formato "porta:banner"

    # Vulnerabilidades (usa cve.verificar_vulnerabilidades_em_banners; base_cves é ignorado na nova versão)
    try:
        from cve import verificar_vulnerabilidades_em_banners
        confirmadas, suspeitas = verificar_vulnerabilidades_em_banners(
            banners, base_cves, detalhado=True
        )
        vulns = [*confirmadas, *[f"{cve} (suspeita)" for cve in suspeitas]]
    except Exception:
        vulns = []

    return {
        "ip": ip,
        "status": "ONLINE",
        "nome": nome,
        "mac": mac,
        "fabricante": fabricante,
        "so": so,
        "portas": portas,
        "banners": banners,
        "vulnerabilidades": vulns,
        "latencia": latencia,
    }
