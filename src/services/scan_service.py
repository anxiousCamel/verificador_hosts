"""
# src/services/scan_service.py — Scanner de hosts e portas

## Descrição
Scanner de rede com detecção de hosts, port scanning paralelo e banner grabbing.

Funcionalidades:
- Ping com extração de TTL e latência (detecção de SO por heurística)
- Resolução reversa de hostname (opcional via ENV)
- Descoberta de MAC via tabela ARP (Windows e Linux)
- Lookup de fabricante por OUI
- Port scan paralelo com banner grabbing em **conexão única** por porta
- Probes específicas por protocolo (HTTP, SSH, SMTP, FTP, etc.)
- Controle global de sockets via semáforo para evitar exaustão
- **Fast alive discovery** — parallel ping all IPs before deep scan

Cada função tem uma única responsabilidade. O módulo **não** faz verificação
de CVEs — essa responsabilidade é de cve_analyzer.py, orquestrado por
core/batch_scanner.py.

## Variáveis de ambiente
- `VH_MAX_SOCKETS`: Limite global de sockets simultâneos (padrão: 256)
- `VH_RESOLVE_HOSTNAME`: "1" para resolver DNS reverso, "0" para pular

Camada: services (sem dependências de projeto — lê apenas ENV)
"""

from __future__ import annotations

import os
import re
import ssl
import socket
import platform
import subprocess
import threading
import time
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager


# ============================
# Configuração via ENV
# ============================

MAX_SOCKETS = int(os.getenv("VH_MAX_SOCKETS", "256"))
RESOLVE_HOSTNAME = os.getenv("VH_RESOLVE_HOSTNAME", "1") == "1"

_socket_semaphore = threading.Semaphore(MAX_SOCKETS)

# Pre-compiled regex for hot paths (avoid re-compile per call)
_RE_LATENCY = re.compile(
    r"(?:time|tempo)[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE
)
_RE_TTL = re.compile(r"ttl[=\s]\s*([0-9]+)", re.IGNORECASE)
_RE_MAC_WIN = None  # Built dynamically per IP
_RE_MAC_LLADDR = re.compile(r"lladdr\s+([0-9a-fA-F:]{17})")
_RE_MAC_GENERIC = re.compile(r"([0-9a-fA-F:]{17})")
_RE_HTTP_SERVER = re.compile(r"\bserver:\s*([^\r\n]+)", re.IGNORECASE)

_IS_WINDOWS = platform.system().lower().startswith("win")


# ============================
# Gerenciamento de conexões
# ============================

@contextmanager
def _managed_connection(ip: str, port: int, timeout: float):
    """
    Context manager que abre uma conexão TCP respeitando o limite global de sockets.

    Adquire o semáforo antes de abrir o socket e garante liberação no finally,
    mesmo em caso de erro. Isso evita exaustão de file descriptors em varreduras
    massivas.

    Args:
        ip: Endereço IP do alvo.
        port: Porta TCP destino.
        timeout: Timeout da conexão em segundos.

    Yields:
        socket.socket: Socket conectado.
    """
    _socket_semaphore.acquire()
    sock = None
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        yield sock
    finally:
        try:
            if sock:
                sock.close()
        finally:
            _socket_semaphore.release()


# ============================
# Definição de portas
# ============================

CRITICAL_PORTS = {
    22, 23,                         # SSH, Telnet
    3389, 5900, 5985, 5986,         # RDP, VNC, WinRM
    135, 137, 138, 139, 445,        # SMB/RPC
}

DEFAULT_SCAN_PORTS = sorted({
    # Administração remota
    22, 23, 3389, 5900, 5985, 5986, 10000,
    # Web
    80, 443, 8080, 8443, 8888, 8000,
    # Bancos de dados
    1433, 1521, 3306, 5432,
    # Compartilhamento/RPC
    135, 137, 138, 139, 445,
    # Email
    25, 465, 587, 110, 995, 143, 993,
    # Infraestrutura
    3000, 3001, 4000, 4001, 6379, 11211, 27017,
    # Impressão
    515, 631, 9100,
})

# Ultra-fast mode: only the most common/critical ports (15 ports vs 40+)
# Reduces scan time by ~60% with minimal information loss
FAST_SCAN_PORTS = sorted({
    22, 23, 80, 443, 135, 139, 445, 3389,  # Critical
    3306, 5432, 8080, 25, 21, 5900, 6379,  # High-value
})

# Portas que usam TLS direto (sem STARTTLS)
TLS_DIRECT_PORTS = {443, 465, 993, 995, 990}


# ============================
# Probes de protocolo
# ============================

SERVICE_PROBES: Dict[int, bytes] = {
    80:   b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8000: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8888: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
    443:  b"",
    22:   b"\r\n",
    25:   b"EHLO example.com\r\n",
    587:  b"EHLO example.com\r\n",
    465:  b"",
    110:  b"USER test\r\n",
    995:  b"",
    143:  b". CAPABILITY\r\n",
    993:  b"",
    21:   b"FEAT\r\n",
    990:  b"",
}

HTTP_PORTS = {80, 8080, 8000, 8888, 8443, 443}


# ============================
# Funções auxiliares de banner
# ============================

def _sanitize_banner(raw: str) -> str:
    """
    Normaliza um banner para uma única linha limpa.

    Remove quebras de linha, troca ';' por ',' (compatibilidade CSV),
    e retorna "-" se vazio.
    """
    if not raw:
        return "-"
    cleaned = raw.replace("\r", " ").replace("\n", " ").strip()
    cleaned = cleaned.replace(";", ",")
    return cleaned or "-"


def _recv_once(sock: socket.socket, buffer_size: int = 2048) -> bytes:
    """Lê um bloco do socket sem retry. Retorna b"" em caso de erro."""
    try:
        return sock.recv(buffer_size)
    except Exception:
        return b""


def _extract_http_server(banner: str) -> str:
    """Extrai o campo 'Server:' de um banner HTTP, se presente."""
    if not banner or banner == "-":
        return banner
    match = _RE_HTTP_SERVER.search(banner)
    if match:
        return _sanitize_banner(f"Server: {match.group(1)}")
    return banner


# ============================
# Banner grabbing (conexão única)
# ============================

def _grab_banner_tls(ip: str, port: int, timeout: float) -> str:
    """Coleta banner via TLS direto (portas como 443, 465, 993, 995, 990)."""
    try:
        with _managed_connection(ip, port, timeout) as raw_sock:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(raw_sock, server_hostname=ip) as tls_sock:
                tls_sock.settimeout(timeout)
                if port == 443:
                    request = b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n"
                    tls_sock.sendall(request)
                data = _recv_once(tls_sock)
                return _sanitize_banner(data.decode(errors="ignore"))
    except Exception:
        return "-"


def _grab_banner_plain(ip: str, port: int, timeout: float) -> str:
    """Coleta banner via TCP plaintext, enviando probe específica se disponível."""
    probe = SERVICE_PROBES.get(port)
    try:
        with _managed_connection(ip, port, timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                try:
                    sock.sendall(probe)
                except Exception:
                    pass
            data = _recv_once(sock)
            return _sanitize_banner(data.decode(errors="ignore"))
    except Exception:
        return "-"


def _scan_single_port(ip: str, port: int, timeout: float) -> Tuple[int, bool, str]:
    """
    Testa uma porta e coleta banner em uma **única conexão**.

    Para portas TLS (443, 465, etc.), usa handshake TLS + probe.
    Para portas plaintext, envia probe de protocolo e lê resposta.

    Returns:
        Tupla (porta, is_open, banner).
    """
    if port in TLS_DIRECT_PORTS:
        banner = _grab_banner_tls(ip, port, timeout)
        is_open = banner != "-"
        return (port, is_open, banner)

    probe = SERVICE_PROBES.get(port)
    try:
        with _managed_connection(ip, port, timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                try:
                    sock.sendall(probe)
                except Exception:
                    pass
            data = _recv_once(sock)
            banner = _sanitize_banner(data.decode(errors="ignore"))
            if port in HTTP_PORTS:
                banner = _extract_http_server(banner)
            return (port, True, banner)
    except Exception:
        return (port, False, "-")


# ============================
# Port scanning paralelo
# ============================

def scan_ports(ip: str, ports: List[int], timeout: float = 2.5,
               workers: int = 64) -> List[Tuple[int, str]]:
    """
    Varre múltiplas portas em paralelo e retorna as abertas com banners.

    Args:
        ip: Endereço IP do alvo.
        ports: Lista de portas a testar.
        timeout: Timeout por conexão em segundos.
        workers: Número máximo de threads no pool.

    Returns:
        Lista de (porta, banner) para portas abertas, ordenada por porta.
    """
    open_ports: List[Tuple[int, str]] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_scan_single_port, ip, port, timeout): port
            for port in ports
        }
        for future in as_completed(futures):
            try:
                port, is_open, banner = future.result()
                if is_open:
                    open_ports.append((port, banner))
            except Exception:
                pass

    open_ports.sort(key=lambda x: x[0])
    return open_ports


# ============================
# Ping / TTL / Latência
# ============================

def _build_ping_args(ip: str, timeout_ms: int = 1000) -> List[str]:
    """
    Constrói os argumentos do comando ping conforme o SO.

    Args:
        ip: Endereço IP do alvo.
        timeout_ms: Timeout em milissegundos.

    Returns:
        Lista de argumentos para subprocess.run.
    """
    if _IS_WINDOWS:
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    # Linux: -W aceita segundos (inteiro), mínimo 1
    timeout_sec = max(1, timeout_ms // 1000)
    return ["ping", "-c", "1", "-W", str(timeout_sec), ip]


def ping_host(ip: str, timeout_ms: int = 1000) -> Tuple[bool, int, float]:
    """
    Executa um ping ICMP e extrai TTL e latência.

    Args:
        ip: Endereço IP do alvo.
        timeout_ms: Timeout em milissegundos (padrão 1000ms).

    Returns:
        Tupla (online, ttl, latency_ms).
    """
    try:
        # subprocess timeout slightly above ping timeout to avoid orphan processes
        proc_timeout = max(2, (timeout_ms / 1000) + 1)
        result = subprocess.run(
            _build_ping_args(ip, timeout_ms),
            capture_output=True, text=True, timeout=proc_timeout
        )
        output = result.stdout + result.stderr
        output_lower = output.lower()
        online = result.returncode == 0 or "bytes=" in output_lower or "ttl=" in output_lower

        if not online:
            return False, -1, -1.0

        # Uses pre-compiled regex (avoid re-compile per call)
        ttl, latency = -1, -1.0
        lat_match = _RE_LATENCY.search(output)
        if lat_match:
            latency = float(lat_match.group(1))

        ttl_match = _RE_TTL.search(output)
        if ttl_match:
            ttl = int(ttl_match.group(1))

        return True, ttl, latency
    except Exception:
        return False, -1, -1.0


def discover_alive_hosts(
    ip_list: List[str],
    max_workers: int = 40,
    timeout_ms: int = 800,
) -> Dict[str, Tuple[int, float]]:
    """
    Fast parallel alive discovery — pings all IPs concurrently.

    This is the SINGLE BIGGEST performance optimization: instead of scanning
    254 hosts sequentially at 3s timeout each (worst case: 762s), we ping
    all in parallel with tight timeout. Offline hosts are eliminated in ~1-2s
    total instead of blocking the port scan phase.

    Args:
        ip_list: List of IPs to check.
        max_workers: Concurrent ping threads (40 is safe for subprocess).
        timeout_ms: Ping timeout in ms (800ms is enough for LAN).

    Returns:
        Dict of alive IPs -> (ttl, latency_ms). Only alive hosts included.
    """
    alive: Dict[str, Tuple[int, float]] = {}
    lock = threading.Lock()

    def _ping_one(ip: str):
        online, ttl, lat = ping_host(ip, timeout_ms)
        if online:
            with lock:
                alive[ip] = (ttl, lat)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(_ping_one, ip_list)

    return alive


# ============================
# Hostname / MAC / SO
# ============================

def resolve_hostname(ip: str) -> str:
    """Resolve hostname via DNS reverso (best-effort)."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "N/D"


def get_mac_from_arp(ip: str) -> str:
    """
    Extrai o MAC address da tabela ARP do SO.

    No Windows usa `arp -a`, no Linux tenta `ip neigh` com fallback para `arp -n`.
    Timeout reduzido para 1s (ARP table is local, no network wait).
    """
    try:
        if _IS_WINDOWS:
            proc = subprocess.run(
                ["arp", "-a", ip], capture_output=True, text=True, timeout=1
            )
            match = re.search(rf"{re.escape(ip)}\s+([0-9a-fA-F\-:]+)", proc.stdout)
            if match:
                return match.group(1).replace("-", ":").lower()
        else:
            proc = subprocess.run(
                ["ip", "neigh", "show", ip], capture_output=True, text=True, timeout=1
            )
            match = _RE_MAC_LLADDR.search(proc.stdout)
            if match:
                return match.group(1).lower()

            proc = subprocess.run(
                ["arp", "-n", ip], capture_output=True, text=True, timeout=1
            )
            match = _RE_MAC_GENERIC.search(proc.stdout)
            if match:
                return match.group(1).lower()
    except Exception:
        pass
    return "N/D"


def detect_os_by_ttl(ttl: int) -> str:
    """Heurística básica de SO baseada apenas no TTL."""
    if ttl < 0:
        return "N/D"
    if ttl <= 70:
        return "Linux/Unix"
    if ttl <= 140:
        return "Windows"
    if ttl <= 255:
        return "Cisco/Appliance"
    return "Desconhecido"


def detect_os_enhanced(ttl: int, open_ports: List[Tuple[int, str]]) -> str:
    """
    Detecção de SO combinando TTL + portas abertas + banners.

    Usa sistema de votação: cada evidência adiciona votos para um SO.
    O SO com mais votos vence. Em empate, o TTL tem prioridade.
    """
    votes = {"Linux/Unix": 0, "Windows": 0, "Cisco/Appliance": 0}

    if 0 < ttl <= 70:
        votes["Linux/Unix"] += 2
    elif 70 < ttl <= 140:
        votes["Windows"] += 2
    elif 140 < ttl <= 255:
        votes["Cisco/Appliance"] += 2

    port_numbers = {p for p, _ in open_ports}

    windows_ports = {135, 139, 445, 3389, 5985, 5986}
    if port_numbers & windows_ports:
        votes["Windows"] += len(port_numbers & windows_ports)

    if 22 in port_numbers and not (port_numbers & {3389, 135, 445}):
        votes["Linux/Unix"] += 1

    for _, banner in open_ports:
        banner_lower = banner.lower()

        if any(w in banner_lower for w in (
            "microsoft", "iis", "windows", "win32", "win64",
            "exchange", "outlook", "ms-wbt-server",
        )):
            votes["Windows"] += 3

        if any(w in banner_lower for w in (
            "openssh", "ubuntu", "debian", "centos", "redhat",
            "fedora", "alpine", "linux", "nginx",
        )):
            votes["Linux/Unix"] += 3

        if any(w in banner_lower for w in (
            "cisco", "ios", "nx-os", "junos", "fortinet",
            "fortigate", "paloalto", "mikrotik",
        )):
            votes["Cisco/Appliance"] += 3

    if all(v == 0 for v in votes.values()):
        return "N/D"

    winner = max(votes, key=votes.get)
    return winner


def lookup_manufacturer(mac: str, oui_table: Dict[str, str]) -> str:
    """
    Busca fabricante pelo OUI (3, 4 ou 5 bytes) do MAC address.

    Tenta match progressivo de 3 até 5 bytes para suportar OUIs estendidos.
    """
    if not mac or mac in ("N/D", "MAC N/D", "-"):
        return "N/D"

    hex_digits = re.sub(r"[^0-9A-Fa-f]", "", mac).upper()
    if len(hex_digits) < 6:
        return "N/D"

    for num_hex in (6, 8, 10):
        if len(hex_digits) >= num_hex:
            plain = hex_digits[:num_hex]
            colon = ":".join(plain[i:i+2] for i in range(0, num_hex, 2))
            if plain in oui_table:
                return oui_table[plain]
            if colon in oui_table:
                return oui_table[colon]

    return "N/D"


# ============================
# Função principal: verificar host
# ============================

def _build_offline_result(ip: str) -> dict:
    """Constrói resultado padrão para host offline."""
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


def scan_host(
    ip: str,
    oui_table: Dict[str, str],
    port_workers: int,
    socket_timeout: float,
    *,
    ports: Optional[List[int]] = None,
) -> dict:
    """
    Executa varredura completa de um host: ping, hostname, MAC, SO e port scan.

    **Não** faz verificação de CVEs — essa responsabilidade é do orquestrador
    (core/batch_scanner.py), que tem visão global e evita processamento duplicado.

    Args:
        ip: Endereço IP do alvo.
        oui_table: Tabela OUI para lookup de fabricante.
        port_workers: Número de threads para o port scan.
        socket_timeout: Timeout por conexão em segundos.
        ports: Custom port list (default: DEFAULT_SCAN_PORTS).

    Returns:
        Dicionário com campos:
        - ip, status, nome, mac, fabricante, so, portas, banners,
          vulnerabilidades (vazio), latencia
    """
    online, ttl, latency = ping_host(ip)
    if not online:
        return _build_offline_result(ip)

    return _scan_alive_host(ip, ttl, latency, oui_table, port_workers, socket_timeout, ports)


def scan_host_prescan(
    ip: str,
    ttl: int,
    latency: float,
    oui_table: Dict[str, str],
    port_workers: int,
    socket_timeout: float,
    *,
    ports: Optional[List[int]] = None,
) -> dict:
    """
    Scan a host that was already confirmed alive by discover_alive_hosts().

    PERFORMANCE: Skips the redundant ping (saves 1-3s per host), goes straight
    to metadata collection and port scanning.

    Args:
        ip: IP address.
        ttl: TTL from discovery phase.
        latency: Latency from discovery phase (ms).
        oui_table: OUI table.
        port_workers: Port scan threads.
        socket_timeout: Socket timeout (seconds).
        ports: Custom port list (default: DEFAULT_SCAN_PORTS).

    Returns:
        Scan result dict.
    """
    return _scan_alive_host(ip, ttl, latency, oui_table, port_workers, socket_timeout, ports)


def _scan_alive_host(
    ip: str,
    ttl: int,
    latency: float,
    oui_table: Dict[str, str],
    port_workers: int,
    socket_timeout: float,
    ports: Optional[List[int]] = None,
) -> dict:
    """Internal: scans a known-alive host (no ping)."""
    hostname = resolve_hostname(ip) if RESOLVE_HOSTNAME else "N/D"
    mac = get_mac_from_arp(ip)
    manufacturer = lookup_manufacturer(mac, oui_table)

    scan_port_list = ports or DEFAULT_SCAN_PORTS

    open_ports = scan_ports(
        ip, scan_port_list,
        timeout=socket_timeout,
        workers=port_workers,
    )

    os_guess = detect_os_enhanced(ttl, open_ports)

    port_numbers = [str(port) for port, _ in open_ports]
    banners = [f"{port}:{banner}" for port, banner in open_ports]

    return {
        "ip": ip,
        "status": "ONLINE",
        "nome": hostname,
        "mac": mac,
        "fabricante": manufacturer,
        "so": os_guess,
        "portas": port_numbers,
        "banners": banners,
        "vulnerabilidades": [],  # Preenchido pelo orquestrador (core/batch_scanner.py)
        "latencia": latency,
    }


# Alias de compatibilidade
verificar_host = scan_host
