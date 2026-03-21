"""
# src/services/recon.py — Fase 1: Descoberta inteligente de hosts

## Filosofia
Descobrir hosts ativos rápido e triagear imediatamente.
Um atacante real não perde tempo com hosts mortos.

## Decisões de design
- Ping paralelo com ThreadPool (rápido, baixo ruído)
- Triagem por TTL (SO) + latência (proximidade)
- Prioridade alta: hosts que respondem rápido + SO identificável
- Prioridade baixa: hosts lentos ou com TTL ambíguo

Camada: services
Dependências: src.services.scan_service, src.models.pentest_models
"""

from __future__ import annotations

from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed

from src.services.scan_service import (
    ping_host, resolve_hostname, get_mac_from_arp,
    lookup_manufacturer, RESOLVE_HOSTNAME,
)
from src.models.pentest_models import HostTarget


def _triage_priority(ttl: int, latency_ms: float) -> int:
    """
    Calcula prioridade de investigação baseado em sinais iniciais.

    Lógica de atacante:
    - Windows (TTL ~128) = prioridade alta (SMB, RDP, WinRM, shares)
    - Linux (TTL ~64) = prioridade média (SSH, web services)
    - Cisco/Appliance (TTL ~255) = prioridade baixa
    - Latência muito alta (>200ms) = reduz prioridade (possível firewall)
    - Latência baixa (<5ms) = aumenta (host próximo, mesmo segmento)

    Returns:
        Prioridade: 1 (baixa), 2 (média), 3 (alta).
    """
    if ttl < 0:
        return 1

    if ttl <= 70:
        priority = 2
    elif ttl <= 140:
        priority = 3
    else:
        priority = 1

    if latency_ms > 200:
        priority = max(1, priority - 1)
    elif latency_ms < 5 and latency_ms > 0:
        priority = min(3, priority + 1)

    return priority


def _discover_single_host(
    ip: str,
    oui_table: Dict[str, str],
) -> HostTarget:
    """
    Faz discovery de um único host (ping + metadata básica).

    Coleta apenas o mínimo necessário para triagem:
    - Está vivo? (ping)
    - Que SO provável? (TTL)
    - Quão perto está? (latência)
    - Hostname e MAC (se disponíveis)

    NÃO faz port scan — responsabilidade da fase 2 (services/enumeration.py).
    """
    target = HostTarget(ip=ip)

    online, ttl, latency = ping_host(ip)
    if not online:
        target.add_decision("RECON", f"Host {ip} não respondeu ao ping → SKIP")
        return target

    target.is_alive = True
    target.ttl = ttl
    target.latency_ms = latency
    target.priority = _triage_priority(ttl, latency)

    if RESOLVE_HOSTNAME:
        target.hostname = resolve_hostname(ip)

    target.mac = get_mac_from_arp(ip)
    if target.mac != "N/D":
        manufacturer = lookup_manufacturer(target.mac, oui_table)
        if manufacturer != "N/D":
            target.add_decision("RECON", f"Fabricante: {manufacturer} (MAC: {target.mac})")
            net_vendors = ("cisco", "juniper", "arista", "fortinet", "paloalto", "mikrotik")
            if any(v in manufacturer.lower() for v in net_vendors):
                target.priority = min(target.priority, 1)
                target.add_decision("RECON", "Fabricante de rede detectado → prioridade reduzida")

    if ttl <= 70:
        target.os_guess = "Linux/Unix"
    elif ttl <= 140:
        target.os_guess = "Windows"
    elif ttl <= 255:
        target.os_guess = "Cisco/Appliance"

    target.add_decision(
        "RECON",
        f"Vivo | TTL={ttl} | SO≈{target.os_guess} | "
        f"Latência={latency:.1f}ms | Prioridade={target.priority}"
    )

    return target


def discover_hosts(
    ip_list: List[str],
    oui_table: Dict[str, str],
    workers: int = 20,
    callback=None,
) -> List[HostTarget]:
    """
    Fase 1: Descoberta paralela e triagem de hosts.

    Executa ping em todos os IPs em paralelo e classifica cada host
    por prioridade de investigação. Hosts mortos são descartados
    imediatamente.

    Args:
        ip_list: Lista de IPs para verificar.
        oui_table: Tabela OUI para lookup de fabricante.
        workers: Número de threads (alto pois ping é I/O-bound e leve).
        callback: Função chamada a cada host descoberto (para progresso).

    Returns:
        Lista de HostTarget, ordenada por prioridade (mais alto primeiro).
    """
    targets: List[HostTarget] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_discover_single_host, ip, oui_table): ip
            for ip in ip_list
        }

        for future in as_completed(futures):
            try:
                target = future.result(timeout=10)
                targets.append(target)
                if callback:
                    callback(target)
            except Exception:
                ip = futures[future]
                t = HostTarget(ip=ip)
                t.add_decision("RECON", f"Erro ao verificar {ip} → SKIP")
                targets.append(t)

    targets.sort(key=lambda t: (-int(t.is_alive), -t.priority, t.ip))
    return targets
