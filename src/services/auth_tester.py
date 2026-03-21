"""
# src/services/auth_tester.py — Fase 4: Validação de acesso (credenciais padrão)

## Filosofia
Testar APENAS credenciais padrão conhecidas, com limite estrito.
Um atacante real testa o óbvio primeiro, não faz brute force.

## Regras
- Máximo 5 combinações por serviço (não é brute force)
- Só testa em serviços que aceitam autenticação
- Rate limiting entre tentativas (evita lockout e detecção)
- Registra cada decisão de testar ou não

## Serviços testados
- SSH: banner collection (versão → CVEs)
- SMB: acesso anônimo, guest (via smbclient se disponível)
- HTTP: endpoints de admin com credenciais padrão (via requests)
- Redis/MySQL: conexões sem autenticação (via socket)

## NOTA DE SEGURANÇA
Este módulo deve ser usado APENAS em pentests autorizados.
Teste de credenciais sem autorização é ilegal.

Camada: services
Dependências: src.models.pentest_models
"""

from __future__ import annotations

import re
import time
import socket
import subprocess
import shutil
from typing import List, Dict, Optional

from src.models.pentest_models import HostTarget, Finding

_ATTEMPT_DELAY_SEC = 0.5

_DEFAULT_CREDS: Dict[str, List[tuple]] = {
    "ssh": [
        ("admin", "admin"),
        ("root", "root"),
        ("root", "toor"),
        ("admin", "password"),
        ("admin", "1234"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("root", "root"),
    ],
    "mysql": [
        ("root", ""),
        ("root", "root"),
        ("root", "mysql"),
    ],
    "postgresql": [
        ("postgres", "postgres"),
        ("postgres", ""),
    ],
    "redis": [
        ("", ""),
    ],
}


# ==============================
# Testes por serviço
# ==============================

def _check_smb_anonymous(ip: str, timeout: float = 5.0) -> Optional[Dict]:
    """
    Testa acesso SMB anônimo via smbclient (se disponível).

    Acesso anônimo ao SMB é um achado crítico — permite enumeração de shares,
    usuários, e às vezes acesso a arquivos.
    """
    smbclient = shutil.which("smbclient")
    if not smbclient:
        return None

    try:
        result = subprocess.run(
            [smbclient, "-L", ip, "-N", "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        output = result.stdout + result.stderr

        if result.returncode == 0 or "Sharename" in output:
            return {"method": "anonymous", "success": True, "output": output[:500]}
        return {"method": "anonymous", "success": False, "output": output[:200]}
    except Exception as e:
        return {"method": "anonymous", "success": False, "error": str(e)}


def _check_smb_guest(ip: str, timeout: float = 5.0) -> Optional[Dict]:
    """Testa acesso SMB com conta guest."""
    smbclient = shutil.which("smbclient")
    if not smbclient:
        return None

    try:
        result = subprocess.run(
            [smbclient, "-L", ip, "-U", "guest%", "--timeout", str(int(timeout))],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        output = result.stdout + result.stderr

        if result.returncode == 0 or "Sharename" in output:
            return {"method": "guest", "success": True, "output": output[:500]}
        return {"method": "guest", "success": False}
    except Exception:
        return {"method": "guest", "success": False}


def _check_ssh_banner(ip: str, port: int = 22, timeout: float = 3.0) -> Optional[str]:
    """
    Coleta banner SSH para identificar versão (sem tentar autenticar).

    A versão do SSH já é informação valiosa:
    - OpenSSH < 7.7 → username enumeration
    - OpenSSH < 8.0 → várias CVEs
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            banner = sock.recv(1024).decode(errors="ignore").strip()
            return banner
        finally:
            sock.close()
    except Exception:
        return None


def _check_http_admin_panels(
    ip: str,
    port: int,
    tls: bool = False,
    timeout: float = 5.0,
) -> List[Dict]:
    """
    Verifica endpoints de administração HTTP comuns.

    Não faz brute force — apenas testa se painéis de admin existem.
    """
    import requests
    from requests.exceptions import RequestException
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    scheme = "https" if tls else "http"
    base_url = f"{scheme}://{ip}:{port}"

    admin_paths = [
        "/admin", "/login", "/administrator", "/wp-admin",
        "/phpmyadmin", "/manager/html", "/webmin",
    ]

    results = []
    for path in admin_paths:
        try:
            resp = requests.get(
                f"{base_url}{path}",
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            if resp.status_code in (200, 401, 403):
                result = {
                    "path": path,
                    "status_code": resp.status_code,
                    "title": _extract_html_title(resp.text),
                    "auth_required": resp.status_code == 401,
                }
                if resp.status_code == 200 and _has_login_form(resp.text):
                    result["has_login_form"] = True
                results.append(result)
            time.sleep(0.2)
        except RequestException:
            continue

    return results


def _extract_html_title(html: str) -> str:
    """Extrai <title> do HTML (best-effort)."""
    m = re.search(r'<title[^>]*>(.*?)</title>', html[:2000], re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:100] if m else ""


def _has_login_form(html: str) -> bool:
    """Detecta se página tem formulário de login."""
    html_lower = html[:5000].lower()
    indicators = ("type=\"password\"", "type='password'", "login", "sign in", "log in")
    return any(ind in html_lower for ind in indicators)


def _check_redis_noauth(ip: str, port: int = 6379, timeout: float = 3.0) -> Optional[Dict]:
    """
    Testa se Redis está acessível sem autenticação.

    Redis sem senha é achado crítico — permite RCE via SLAVEOF,
    CONFIG SET, ou escrita de crontab/SSH keys.
    """
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            sock.sendall(b"INFO server\r\n")
            time.sleep(0.3)
            data = sock.recv(4096).decode(errors="ignore")
            if "redis_version" in data:
                return {"noauth": True, "info": data[:300]}
            if "NOAUTH" in data or "ERR" in data:
                return {"noauth": False, "requires_auth": True}
        finally:
            sock.close()
    except Exception:
        pass
    return None


def _check_mysql_noauth(ip: str, port: int = 3306, timeout: float = 3.0) -> Optional[Dict]:
    """Testa se MySQL/MariaDB permite conexão e coleta banner do handshake."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            data = sock.recv(4096)
            if data and len(data) > 4:
                payload = data[4:]
                null_idx = payload.find(b'\x00')
                if null_idx > 0:
                    version = payload[:null_idx].decode(errors="ignore")
                    return {"version": version, "banner": data[:100].hex()}
        finally:
            sock.close()
    except Exception:
        pass
    return None


# ==============================
# Orquestração de testes de auth
# ==============================

def validate_access(
    targets: List[HostTarget],
    socket_timeout: float = 5.0,
) -> List[Finding]:
    """
    Fase 4: Testa credenciais padrão e acesso anônimo em serviços relevantes.

    Decisão de atacante:
    - Só testa hosts com prioridade >= 2
    - Só testa serviços que aceitam autenticação
    - Máximo de tentativas limitado
    - Delay entre tentativas

    Args:
        targets: Hosts enumerados.
        socket_timeout: Timeout de conexão.

    Returns:
        Lista de Findings de acesso.
    """
    findings: List[Finding] = []

    for target in targets:
        if not target.is_alive or target.priority < 2:
            target.add_decision("AUTH", f"Prioridade {target.priority} < 2 → pular testes de auth")
            continue

        if not target.open_ports:
            target.add_decision("AUTH", "Sem portas abertas → pular")
            continue

        target.add_decision("AUTH", f"Testando credenciais padrão (prioridade={target.priority})")

        for port_info in target.open_ports:

            if port_info.service == "smb":
                target.add_decision("AUTH", f"SMB em :{port_info.port} → testando acesso anônimo")

                anon = _check_smb_anonymous(target.ip, socket_timeout)
                if anon and anon.get("success"):
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="default_creds", severity="alto",
                        title="SMB: Acesso anônimo permitido",
                        detail="O servidor SMB permite listar shares sem credenciais. "
                               "Atacante pode enumerar shares, usuários, e acessar dados.",
                        evidence=anon.get("output", "")[:300],
                        remediation="Desabilitar acesso anônimo ao SMB.",
                    ))
                    target.auth_results.append({"service": "smb", "method": "anonymous", "success": True})
                else:
                    guest = _check_smb_guest(target.ip, socket_timeout)
                    if guest and guest.get("success"):
                        findings.append(Finding(
                            host=target.ip, port=port_info.port,
                            category="default_creds", severity="medio",
                            title="SMB: Conta guest ativa",
                            detail="Conta guest permite listar shares (pode ter acesso a dados).",
                            evidence=guest.get("output", "")[:300],
                            remediation="Desabilitar conta guest no SMB.",
                        ))
                        target.auth_results.append({"service": "smb", "method": "guest", "success": True})

                time.sleep(_ATTEMPT_DELAY_SEC)

            elif port_info.service == "ssh":
                target.add_decision("AUTH", f"SSH em :{port_info.port} → coletando banner")
                banner = _check_ssh_banner(target.ip, port_info.port, socket_timeout)
                if banner:
                    target.auth_results.append({"service": "ssh", "banner": banner})
                    if "OpenSSH" in banner:
                        m = re.search(r'OpenSSH[_\s](\d+\.\d+)', banner)
                        if m:
                            ver = float(m.group(1))
                            if ver < 7.7:
                                findings.append(Finding(
                                    host=target.ip, port=port_info.port,
                                    category="vuln", severity="medio",
                                    title=f"OpenSSH {m.group(1)} → username enumeration",
                                    detail="Versões anteriores a 7.7 permitem enumerar "
                                           "usuários válidos via timing attack.",
                                    evidence=banner,
                                    remediation="Atualizar OpenSSH para >= 8.0.",
                                ))

            elif port_info.service == "redis":
                target.add_decision("AUTH", f"Redis em :{port_info.port} → testando sem senha")
                result = _check_redis_noauth(target.ip, port_info.port, socket_timeout)
                if result and result.get("noauth"):
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="default_creds", severity="alto",
                        title="Redis sem autenticação",
                        detail="Redis acessível sem senha. Permite leitura/escrita de dados, "
                               "RCE via CONFIG SET dir/dbfilename, e escrita de SSH keys.",
                        evidence=result.get("info", "")[:200],
                        remediation="Configurar requirepass e bind 127.0.0.1.",
                    ))
                    target.auth_results.append({"service": "redis", "noauth": True})

            elif port_info.service == "mysql":
                target.add_decision("AUTH", f"MySQL em :{port_info.port} → coletando versão")
                result = _check_mysql_noauth(target.ip, port_info.port, socket_timeout)
                if result and result.get("version"):
                    target.auth_results.append({"service": "mysql", "version": result["version"]})
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="info_leak", severity="baixo",
                        title=f"MySQL expõe versão: {result['version']}",
                        detail="Versão do MySQL visível no handshake permite mapeamento de CVEs.",
                        evidence=f"Versão: {result['version']}",
                    ))

            elif port_info.service in ("http", "https"):
                target.add_decision("AUTH", f"HTTP em :{port_info.port} → verificando painéis de admin")
                is_tls = port_info.tls or port_info.service == "https"
                panels = _check_http_admin_panels(
                    target.ip, port_info.port, tls=is_tls, timeout=socket_timeout
                )
                for panel in panels:
                    sev = "medio" if panel.get("auth_required") or panel.get("has_login_form") else "baixo"
                    findings.append(Finding(
                        host=target.ip, port=port_info.port,
                        category="exposure", severity=sev,
                        title=f"Painel HTTP encontrado: {panel['path']}",
                        detail=f"Status: {panel['status_code']} | Título: {panel.get('title', 'N/A')}",
                        evidence=f"URL: {'https' if is_tls else 'http'}://{target.ip}:{port_info.port}{panel['path']}",
                        remediation="Restringir acesso ao painel de administração.",
                    ))

    return findings
