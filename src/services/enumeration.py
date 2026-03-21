"""
# src/services/enumeration.py — Fase 2-3: Enumeração direcionada + Análise

## Filosofia
Não escanear todas as portas em todos os hosts.
Escolher O QUE testar baseado NO QUE já sabemos.

## Decisões inteligentes
- Host Windows (TTL ~128) → testar SMB (445), RDP (3389), WinRM (5985/5986)
- Host Linux (TTL ~64) → testar SSH (22), HTTP (80/443), bancos de dados
- Prioridade alta → scan completo de portas
- Prioridade baixa → apenas portas críticas

## Análise de serviços
- Identifica serviço pelo banner (não apenas pela porta)
- Mapeia versão → vulnerabilidades conhecidas
- Classifica cada porta por criticidade para pentest

Camada: services
Dependências: src.services.scan_service, src.services.cve_analyzer, src.models.pentest_models
"""

from __future__ import annotations

import re
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.services.scan_service import (
    scan_ports, detect_os_enhanced, CRITICAL_PORTS, DEFAULT_SCAN_PORTS,
)
from src.models.pentest_models import HostTarget, PortInfo, Finding


# ==============================
# Seleção inteligente de portas
# ==============================

_WINDOWS_PRIORITY_PORTS = sorted({
    22, 80, 443, 135, 139, 445, 3389, 5985, 5986,
    1433, 8080, 8443,
    3306, 5432,
    25, 110, 143,
})

_LINUX_PRIORITY_PORTS = sorted({
    22, 80, 443, 8080, 8443, 8000, 8888,
    3306, 5432, 6379, 27017, 11211,
    25, 110, 143,
    21,
    3000, 3001, 4000, 9100,
})

_APPLIANCE_PRIORITY_PORTS = sorted({
    22, 23, 80, 443, 8443, 161,
})

_PORT_SERVICE_MAP: Dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    80: "http", 110: "pop3", 135: "msrpc", 137: "netbios",
    138: "netbios", 139: "netbios", 143: "imap", 443: "https",
    445: "smb", 465: "smtps", 587: "smtp", 631: "ipp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 5985: "winrm", 5986: "winrm",
    6379: "redis", 8080: "http", 8443: "https", 8000: "http",
    8888: "http", 9100: "jetdirect", 10000: "webmin",
    11211: "memcached", 27017: "mongodb",
    3000: "http", 3001: "http", 4000: "http", 4001: "http",
    515: "lpd", 990: "ftps",
}

_CRITICAL_SERVICES = {
    "smb", "rdp", "ssh", "telnet", "winrm", "vnc", "ftp",
    "mssql", "mysql", "postgresql", "redis", "mongodb", "memcached",
}


def _select_ports_for_host(target: HostTarget) -> List[int]:
    """
    Seleciona portas a escanear baseado no perfil do host.

    - Prioridade 3 (alta) → scan completo
    - Prioridade 2 (média) → portas por perfil de SO
    - Prioridade 1 (baixa) → apenas portas críticas mínimas
    """
    if target.priority >= 3:
        target.add_decision("ENUM", "Prioridade ALTA → scan completo de portas")
        return DEFAULT_SCAN_PORTS

    if target.priority >= 2:
        if target.os_guess == "Windows":
            target.add_decision("ENUM", "Windows + prioridade MÉDIA → portas Windows prioritárias")
            return _WINDOWS_PRIORITY_PORTS
        elif target.os_guess in ("Linux/Unix",):
            target.add_decision("ENUM", "Linux + prioridade MÉDIA → portas Linux prioritárias")
            return _LINUX_PRIORITY_PORTS
        else:
            target.add_decision("ENUM", "SO desconhecido + prioridade MÉDIA → portas padrão")
            return DEFAULT_SCAN_PORTS

    if target.os_guess == "Cisco/Appliance":
        target.add_decision("ENUM", "Appliance + prioridade BAIXA → portas mínimas de admin")
        return _APPLIANCE_PRIORITY_PORTS

    target.add_decision("ENUM", "Prioridade BAIXA → apenas portas mais críticas")
    return sorted({22, 23, 80, 443, 445, 3389})


def _identify_service(port: int, banner: str) -> Tuple[str, str, str]:
    """
    Identifica serviço, produto e versão a partir de porta e banner.

    Estratégia em camadas:
    1. Tenta extrair do banner (mais confiável)
    2. Fallback para mapeamento por porta

    Returns:
        Tupla (service, product, version).
    """
    banner_lower = (banner or "").lower()

    if "ssh" in banner_lower:
        return "ssh", _extract_product(banner), _extract_version(banner)
    if "http" in banner_lower or "server:" in banner_lower:
        svc = "https" if port in (443, 8443) else "http"
        return svc, _extract_product(banner), _extract_version(banner)
    if "smtp" in banner_lower or "esmtp" in banner_lower or "postfix" in banner_lower:
        return "smtp", _extract_product(banner), _extract_version(banner)
    if "ftp" in banner_lower:
        return "ftp", _extract_product(banner), _extract_version(banner)
    if "mysql" in banner_lower or "mariadb" in banner_lower:
        return "mysql", _extract_product(banner), _extract_version(banner)
    if "postgresql" in banner_lower:
        return "postgresql", _extract_product(banner), _extract_version(banner)
    if "redis" in banner_lower:
        return "redis", _extract_product(banner), _extract_version(banner)
    if "imap" in banner_lower or "dovecot" in banner_lower:
        return "imap", _extract_product(banner), _extract_version(banner)
    if "pop" in banner_lower:
        return "pop3", _extract_product(banner), _extract_version(banner)
    if "mongodb" in banner_lower:
        return "mongodb", _extract_product(banner), _extract_version(banner)

    service = _PORT_SERVICE_MAP.get(port, "unknown")
    return service, _extract_product(banner), _extract_version(banner)


def _extract_product(banner: str) -> str:
    """Extrai nome do produto do banner (best-effort)."""
    if not banner or banner == "-":
        return ""
    m = re.search(r'([A-Za-z][A-Za-z0-9_\-]+)[/_\s]v?[0-9]', banner, re.IGNORECASE)
    if m:
        return m.group(1).strip().lower()
    return ""


def _extract_version(banner: str) -> str:
    """Extrai versão do banner (best-effort)."""
    if not banner or banner == "-":
        return ""
    m = re.search(r'(\d+\.\d+(?:\.\d+)?(?:[a-z][0-9a-z]*)?)', banner)
    return m.group(1) if m else ""


# ==============================
# Enumeração por host
# ==============================

def _enumerate_single_host(
    target: HostTarget,
    port_workers: int,
    socket_timeout: float,
) -> HostTarget:
    """
    Enumera portas e serviços de um único host.

    Fluxo:
    1. Seleciona portas baseado no perfil (SO + prioridade)
    2. Scan paralelo das portas selecionadas
    3. Identifica serviços e versões
    4. Refina estimativa de SO com dados de portas/banners
    5. Classifica criticidade de cada porta
    """
    ports_to_scan = _select_ports_for_host(target)

    open_ports = scan_ports(
        target.ip, ports_to_scan,
        timeout=socket_timeout,
        workers=port_workers,
    )

    if not open_ports:
        target.add_decision("ENUM", "Nenhuma porta aberta → host pode ter firewall ativo")
        return target

    for port, banner in open_ports:
        service, product, version = _identify_service(port, banner)
        is_critical = port in CRITICAL_PORTS or service in _CRITICAL_SERVICES

        port_info = PortInfo(
            port=port,
            banner=banner,
            service=service,
            version=version,
            product=product,
            is_critical=is_critical,
            tls=port in (443, 465, 993, 995, 990, 8443),
        )
        target.open_ports.append(port_info)

    target.os_guess = detect_os_enhanced(target.ttl, open_ports)

    if target.critical_ports:
        old_priority = target.priority
        target.priority = max(target.priority, 2)
        if any(p.service in ("smb", "rdp", "winrm", "telnet") for p in target.critical_ports):
            target.priority = 3
        if target.priority != old_priority:
            target.add_decision(
                "ENUM",
                f"Portas críticas encontradas → prioridade {old_priority}→{target.priority}"
            )

    services_found = [f"{p.port}/{p.service}" for p in target.open_ports]
    target.add_decision(
        "ENUM",
        f"{len(target.open_ports)} portas abertas: {', '.join(services_found)}"
    )

    return target


# ==============================
# Análise de vulnerabilidades
# ==============================

def _analyze_services(target: HostTarget) -> List[Finding]:
    """
    Fase 3: Analisa serviços encontrados e gera achados.

    Verifica:
    - Serviços intrinsecamente perigosos (Telnet, FTP sem TLS, etc.)
    - Versões conhecidamente vulneráveis (via CVE)
    - Misconfigurations comuns
    """
    findings: List[Finding] = []

    for port_info in target.open_ports:

        if port_info.service == "telnet":
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="alto",
                title="Telnet exposto",
                detail="Telnet transmite credenciais em texto plano. Qualquer atacante no "
                       "mesmo segmento pode interceptar login/senha via sniffing.",
                evidence=f"Porta {port_info.port} aberta, banner: {port_info.banner}",
                remediation="Desabilitar Telnet e usar SSH.",
            ))
            target.add_decision("ANÁLISE", f"Telnet em :{port_info.port} → risco ALTO")

        if port_info.service == "ftp" and not port_info.tls:
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="medio",
                title="FTP sem TLS exposto",
                detail="FTP transmite credenciais e dados em texto plano.",
                evidence=f"Porta {port_info.port}, banner: {port_info.banner}",
                remediation="Migrar para SFTP ou FTPS.",
            ))

        if port_info.service == "rdp":
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="medio",
                title="RDP exposto",
                detail="RDP é alvo frequente de ataques (BlueKeep, brute force). "
                       "Exposição em rede interna aumenta superfície de ataque lateral.",
                evidence=f"Porta {port_info.port} aberta",
                remediation="Restringir acesso RDP via firewall/VPN. Habilitar NLA.",
            ))

        if port_info.service == "vnc":
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="alto",
                title="VNC exposto",
                detail="VNC frequentemente usa autenticação fraca ou nenhuma. "
                       "Permite controle remoto completo da máquina.",
                evidence=f"Porta {port_info.port} aberta, banner: {port_info.banner}",
                remediation="Desabilitar VNC ou proteger com VPN/túnel SSH.",
            ))

        if port_info.service in ("redis", "memcached", "mongodb"):
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="alto",
                title=f"{port_info.service.upper()} exposto sem autenticação provável",
                detail=f"{port_info.service} frequentemente roda sem autenticação. "
                       f"Permite leitura/escrita de dados e potencial RCE.",
                evidence=f"Porta {port_info.port} aberta, banner: {port_info.banner}",
                remediation="Habilitar autenticação e restringir bind address.",
            ))

        if port_info.service == "smb":
            findings.append(Finding(
                host=target.ip, port=port_info.port,
                category="exposure", severity="medio",
                title="SMB exposto",
                detail="SMB é vetor para EternalBlue, relay attacks, e enumeração "
                       "de shares/usuários. Versões antigas (SMBv1) são especialmente perigosas.",
                evidence=f"Porta {port_info.port} aberta",
                remediation="Desabilitar SMBv1. Restringir acesso por firewall.",
            ))

    # CVE matching
    if any(p.version for p in target.open_ports):
        try:
            from src.services.cve_analyzer import verificar_vulnerabilidades_em_banners
            banners = [f"{p.port}:{p.banner}" for p in target.open_ports if p.banner != "-"]
            if banners:
                confirmed, suspected = verificar_vulnerabilidades_em_banners(
                    banners, detalhado=True
                )
                for cve_id in confirmed:
                    findings.append(Finding(
                        host=target.ip, port=0,
                        category="cve", severity="alto",
                        title=f"CVE confirmado: {cve_id}",
                        detail="Versão do serviço corresponde a faixa vulnerável no NVD.",
                        cve_ids=[cve_id],
                        remediation="Atualizar o serviço para versão corrigida.",
                    ))
                for cve_id in suspected[:10]:
                    findings.append(Finding(
                        host=target.ip, port=0,
                        category="cve", severity="baixo",
                        title=f"CVE suspeito: {cve_id}",
                        detail="Produto identificado mas versão exata não confirmada.",
                        cve_ids=[cve_id],
                    ))
                if confirmed:
                    target.add_decision(
                        "ANÁLISE", f"{len(confirmed)} CVEs confirmados → risco ALTO"
                    )
        except Exception:
            pass

    return findings


# ==============================
# API pública
# ==============================

def enumerate_targets(
    targets: List[HostTarget],
    port_workers: int = 4,
    socket_timeout: float = 2.5,
    host_workers: int = 6,
    callback=None,
) -> Tuple[List[HostTarget], List[Finding]]:
    """
    Fase 2-3: Enumeração direcionada + análise de serviços.

    Processa apenas hosts vivos, com paralelismo controlado.
    Cada host recebe scan personalizado baseado no seu perfil.

    Args:
        targets: Hosts da fase 1.
        port_workers: Threads para port scan por host.
        socket_timeout: Timeout de conexão.
        host_workers: Threads para processar hosts em paralelo.
        callback: Função para reportar progresso.

    Returns:
        Tupla (targets_enriquecidos, findings).
    """
    alive = [t for t in targets if t.is_alive]
    all_findings: List[Finding] = []

    with ThreadPoolExecutor(max_workers=host_workers) as executor:
        futures = {
            executor.submit(_enumerate_single_host, t, port_workers, socket_timeout): t
            for t in alive
        }

        for future in as_completed(futures):
            try:
                target = future.result(timeout=(socket_timeout * 2) + 10)
                findings = _analyze_services(target)
                target.findings.extend(findings)
                all_findings.extend(findings)

                if callback:
                    callback(target)
            except Exception:
                pass

    return targets, all_findings
