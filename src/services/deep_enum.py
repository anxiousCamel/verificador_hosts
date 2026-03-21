"""
# src/services/deep_enum.py — Fase 5: Enumeração profunda

## Filosofia
Só aprofundar onde faz sentido — quando há acesso confirmado
ou serviço relevante que justifique investigação adicional.

## Decisão de gate
- SMB: Só se acesso anônimo/guest confirmado na fase 4
- HTTP: Só em hosts com prioridade alta
- Só hosts com achados de severity "alto" ou "medio"

## O que NÃO faz
- Brute force de diretórios (ruidoso e lento)
- Exploração ativa de vulnerabilidades
- Download de arquivos

Camada: services
Dependências: src.models.pentest_models
"""

from __future__ import annotations

import subprocess
import shutil
import time
from typing import List, Dict, Optional

from src.models.pentest_models import HostTarget, Finding


def _enumerate_smb_shares(ip: str, timeout: float = 10.0) -> List[Dict]:
    """
    Lista shares SMB (requer smbclient).

    Tenta acesso anônimo. Se funcionar, lista shares e verifica
    quais permitem leitura.
    """
    smbclient = shutil.which("smbclient")
    if not smbclient:
        return []

    shares = []
    try:
        result = subprocess.run(
            [smbclient, "-L", ip, "-N", "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        output = result.stdout

        in_shares = False
        for line in output.splitlines():
            if "Sharename" in line:
                in_shares = True
                continue
            if in_shares and "---" in line:
                continue
            if in_shares and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0].strip()
                    share_type = parts[1].strip() if len(parts) > 1 else ""
                    if share_name and share_name not in ("Sharename",):
                        share_info = {
                            "name": share_name,
                            "type": share_type,
                            "readable": _check_share_readable(ip, share_name, timeout),
                        }
                        shares.append(share_info)
            elif in_shares and not line.strip():
                in_shares = False

    except Exception:
        pass

    return shares


def _check_share_readable(ip: str, share_name: str, timeout: float = 5.0) -> bool:
    """Verifica se uma share SMB é legível anonimamente."""
    smbclient = shutil.which("smbclient")
    if not smbclient:
        return False

    try:
        result = subprocess.run(
            [smbclient, f"//{ip}/{share_name}", "-N", "-c", "dir",
             "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 3,
        )
        return result.returncode == 0 and ("blocks" in result.stdout.lower() or "\n" in result.stdout)
    except Exception:
        return False


def _enumerate_http_info(
    ip: str,
    port: int,
    tls: bool = False,
    timeout: float = 5.0,
) -> Dict:
    """
    Coleta informações do servidor HTTP.

    Verifica:
    - Headers de segurança (ou falta deles)
    - Tecnologias expostas (X-Powered-By, Server, etc.)
    - robots.txt (pode revelar paths sensíveis)
    """
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scheme = "https" if tls else "http"
    base = f"{scheme}://{ip}:{port}"
    info: Dict = {"headers": {}, "missing_security_headers": [], "robots_txt": None}

    try:
        resp = requests.get(base, timeout=timeout, verify=False, allow_redirects=True)

        interesting = [
            "Server", "X-Powered-By", "X-AspNet-Version",
            "X-Generator", "Via", "X-Frame-Options",
            "Content-Security-Policy", "Strict-Transport-Security",
            "X-Content-Type-Options", "X-XSS-Protection",
        ]
        for header in interesting:
            val = resp.headers.get(header)
            if val:
                info["headers"][header] = val

        security_headers = [
            "X-Frame-Options", "Content-Security-Policy",
            "Strict-Transport-Security", "X-Content-Type-Options",
        ]
        for h in security_headers:
            if h not in resp.headers:
                info["missing_security_headers"].append(h)

    except Exception:
        pass

    try:
        resp = requests.get(f"{base}/robots.txt", timeout=timeout, verify=False)
        if resp.status_code == 200 and "disallow" in resp.text.lower():
            info["robots_txt"] = resp.text[:1000]
    except Exception:
        pass

    return info


def deep_enumerate(
    targets: List[HostTarget],
    socket_timeout: float = 5.0,
) -> List[Finding]:
    """
    Fase 5: Enumeração profunda em alvos selecionados.

    Gate de decisão:
    - Só processa hosts com prioridade >= 2
    - SMB: só se acesso anônimo/guest foi confirmado na fase 4
    - HTTP: headers e info em hosts de alta prioridade

    Args:
        targets: Hosts das fases anteriores.
        socket_timeout: Timeout.

    Returns:
        Lista de Findings adicionais.
    """
    findings: List[Finding] = []

    for target in targets:
        if not target.is_alive or target.priority < 2:
            continue

        # --- SMB Deep Enum ---
        smb_access = any(
            r.get("service") == "smb" and r.get("success")
            for r in target.auth_results
        )

        if target.has_service("smb") and smb_access:
            target.add_decision("DEEP", "SMB com acesso → enumerando shares")
            shares = _enumerate_smb_shares(target.ip, socket_timeout)
            target.smb_shares = [s["name"] for s in shares]

            for share in shares:
                severity = "alto" if share["readable"] else "baixo"
                findings.append(Finding(
                    host=target.ip, port=445,
                    category="info_leak" if share["readable"] else "exposure",
                    severity=severity,
                    title=f"SMB Share: {share['name']} ({'LEGÍVEL' if share['readable'] else 'listada'})",
                    detail=f"Share '{share['name']}' ({share['type']}) "
                           f"{'permite leitura anônima' if share['readable'] else 'visível mas sem acesso confirmado'}.",
                    remediation="Restringir permissões da share. Remover acesso anônimo.",
                ))

            if shares:
                target.add_decision(
                    "DEEP",
                    f"{len(shares)} shares encontrados, "
                    f"{sum(1 for s in shares if s['readable'])} legíveis"
                )
        elif target.has_service("smb"):
            target.add_decision("DEEP", "SMB sem acesso confirmado → pular enumeração de shares")

        # --- HTTP Deep Enum ---
        http_ports = [p for p in target.open_ports if p.service in ("http", "https")]
        if http_ports and target.priority >= 2:
            for port_info in http_ports[:2]:
                target.add_decision("DEEP", f"HTTP em :{port_info.port} → coletando headers/info")
                is_tls = port_info.tls or port_info.service == "https"
                info = _enumerate_http_info(
                    target.ip, port_info.port, tls=is_tls, timeout=socket_timeout
                )

                missing = info.get("missing_security_headers", [])
                if missing:
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="misconfig", severity="baixo",
                        title=f"Headers de segurança HTTP faltantes ({len(missing)})",
                        detail=f"Faltam: {', '.join(missing)}",
                        remediation="Configurar headers de segurança no servidor web.",
                    ))

                exposed_tech = {k: v for k, v in info.get("headers", {}).items()
                                if k in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator")}
                if exposed_tech:
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="info_leak", severity="baixo",
                        title="Tecnologias expostas via headers HTTP",
                        detail=f"Headers revelam: {exposed_tech}",
                        evidence=str(exposed_tech),
                        remediation="Remover headers que expõem tecnologia (Server, X-Powered-By).",
                    ))

                robots = info.get("robots_txt")
                if robots:
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="info_leak", severity="baixo",
                        title="robots.txt revela paths",
                        detail="robots.txt encontrado com regras de Disallow.",
                        evidence=robots[:300],
                        remediation="Revisar robots.txt para não expor paths sensíveis.",
                    ))

                target.http_paths.append({
                    "port": port_info.port,
                    "headers": info.get("headers", {}),
                    "missing_security": missing,
                    "robots": bool(robots),
                })

    return findings
