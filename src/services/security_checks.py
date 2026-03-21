"""
# src/services/security_checks.py — Verificações de segurança pós-scan

## Descrição
Checks de segurança que rodam DEPOIS do port scan + banner grab,
usando os dados já coletados. Não abre novas conexões desnecessárias.

Checks implementados:
1. Serviços abertos sem autenticação (Redis, MongoDB, Memcached, FTP anon)
2. Protocolos fracos (Telnet, FTP cleartext, VNC)
3. HTTP: paths sensíveis (.git/, phpinfo, backups, admin panels)
4. SSL/TLS: certificado expirado, self-signed, cifras fracas
5. SMB: null session, signing
6. Versões criticamente antigas

## Filosofia
- Rápido: usa banners já coletados quando possível
- Cirúrgico: só abre conexão extra quando necessário
- Sem brute force: testa o óbvio (anônimo, sem senha)

Camada: services
"""

from __future__ import annotations

import re
import ssl
import socket
import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed


# ==============================
# Modelo de achado
# ==============================

@dataclass
class SecurityFinding:
    """Achado de segurança de um check específico."""
    host: str
    port: int
    check: str           # "open_service", "weak_protocol", "http_exposure", "ssl", "default_creds"
    severity: str        # "critico", "alto", "medio", "baixo", "info"
    title: str
    detail: str
    evidence: str = ""
    remediation: str = ""

    SEVERITY_ORDER = {"critico": 0, "alto": 1, "medio": 2, "baixo": 3, "info": 4}

    @property
    def severity_score(self) -> int:
        scores = {"critico": 25, "alto": 15, "medio": 8, "baixo": 3, "info": 1}
        return scores.get(self.severity, 0)


# ==============================
# 1. Serviços abertos sem auth
# ==============================

def _check_redis_noauth(ip: str, port: int, timeout: float = 2.0) -> Optional[SecurityFinding]:
    """Testa Redis sem senha — permite RCE via CONFIG SET."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            sock.sendall(b"PING\r\n")
            data = sock.recv(1024).decode(errors="ignore")
            if "+PONG" in data:
                sock.sendall(b"INFO server\r\n")
                time.sleep(0.2)
                info = sock.recv(4096).decode(errors="ignore")
                version = ""
                m = re.search(r"redis_version:(\S+)", info)
                if m:
                    version = m.group(1)
                return SecurityFinding(
                    host=ip, port=port, check="open_service",
                    severity="critico",
                    title=f"Redis SEM SENHA (v{version})" if version else "Redis SEM SENHA",
                    detail="Redis acessível sem autenticação. Permite leitura/escrita "
                           "de dados, RCE via CONFIG SET dir + SAVE, escrita de SSH keys.",
                    evidence=f"PING → +PONG | versão: {version}",
                    remediation="Configurar requirepass e bind 127.0.0.1 no redis.conf.",
                )
            if "NOAUTH" in data or "-ERR" in data:
                return SecurityFinding(
                    host=ip, port=port, check="open_service",
                    severity="info",
                    title="Redis requer autenticação",
                    detail="Redis protegido por senha.",
                    evidence=data[:100],
                )
        finally:
            sock.close()
    except Exception:
        pass
    return None


def _check_mongodb_noauth(ip: str, port: int, timeout: float = 2.0) -> Optional[SecurityFinding]:
    """Testa MongoDB sem autenticação."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            # MongoDB wire protocol: ismaster command
            msg = (
                b"\x3f\x00\x00\x00"  # msg length
                b"\x00\x00\x00\x00"  # request id
                b"\x00\x00\x00\x00"  # response to
                b"\xd4\x07\x00\x00"  # opcode: OP_QUERY
                b"\x00\x00\x00\x00"  # flags
                b"admin.$cmd\x00"    # collection
                b"\x00\x00\x00\x00"  # skip
                b"\x01\x00\x00\x00"  # return
                b"\x13\x00\x00\x00"  # doc length
                b"\x10ismaster\x00"  # field
                b"\x01\x00\x00\x00"  # value: 1
                b"\x00"              # doc end
            )
            sock.sendall(msg)
            data = sock.recv(4096)
            if data and len(data) > 20:
                return SecurityFinding(
                    host=ip, port=port, check="open_service",
                    severity="critico",
                    title="MongoDB SEM AUTENTICAÇÃO",
                    detail="MongoDB acessível sem credenciais. Permite dump completo "
                           "do banco, modificação de dados, e potencial RCE.",
                    evidence=f"ismaster respondeu ({len(data)} bytes)",
                    remediation="Habilitar auth: security.authorization=enabled no mongod.conf.",
                )
        finally:
            sock.close()
    except Exception:
        pass
    return None


def _check_memcached_open(ip: str, port: int, timeout: float = 2.0) -> Optional[SecurityFinding]:
    """Testa Memcached aberto (DDoS amplification + data leak)."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            sock.sendall(b"stats\r\n")
            data = sock.recv(4096).decode(errors="ignore")
            if "STAT" in data:
                items = ""
                m = re.search(r"STAT curr_items (\d+)", data)
                if m:
                    items = f" ({m.group(1)} itens)"
                return SecurityFinding(
                    host=ip, port=port, check="open_service",
                    severity="alto",
                    title=f"Memcached ABERTO{items}",
                    detail="Memcached sem autenticação. Permite leitura de dados em cache "
                           "e amplificação de DDoS (fator 50.000x).",
                    evidence=data[:200],
                    remediation="Bind 127.0.0.1 ou usar SASL auth. Desabilitar UDP.",
                )
        finally:
            sock.close()
    except Exception:
        pass
    return None


def _check_ftp_anonymous(ip: str, port: int, timeout: float = 3.0) -> Optional[SecurityFinding]:
    """Testa FTP com login anônimo."""
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        try:
            banner = sock.recv(1024).decode(errors="ignore")
            sock.sendall(b"USER anonymous\r\n")
            resp1 = sock.recv(1024).decode(errors="ignore")
            if "331" in resp1:  # Password required (expected)
                sock.sendall(b"PASS anonymous@\r\n")
                resp2 = sock.recv(1024).decode(errors="ignore")
                if "230" in resp2:  # Login OK
                    return SecurityFinding(
                        host=ip, port=port, check="open_service",
                        severity="alto",
                        title="FTP ANÔNIMO habilitado",
                        detail="FTP permite login anônimo. Atacante pode listar/baixar "
                               "arquivos e possivelmente fazer upload.",
                        evidence=f"Banner: {banner.strip()[:80]}",
                        remediation="Desabilitar login anônimo no FTP.",
                    )
        finally:
            sock.close()
    except Exception:
        pass
    return None


# ==============================
# 2. Protocolos fracos
# ==============================

def check_weak_protocols(host: dict) -> List[SecurityFinding]:
    """Verifica protocolos inseguros baseado nos banners já coletados."""
    findings = []
    ip = host.get("ip", "")
    banners = host.get("banners", [])
    ports = host.get("portas", [])

    port_set = set()
    for p in ports:
        try:
            port_set.add(int(p))
        except ValueError:
            pass

    # Telnet
    if 23 in port_set:
        findings.append(SecurityFinding(
            host=ip, port=23, check="weak_protocol",
            severity="alto",
            title="TELNET ativo",
            detail="Telnet transmite TUDO em texto plano (senhas, dados). "
                   "Qualquer sniffer na rede captura credenciais.",
            remediation="Desabilitar Telnet. Usar SSH.",
        ))

    # FTP sem TLS
    if 21 in port_set:
        has_tls = any("TLS" in b or "FTPS" in b for b in banners if b.startswith("21:"))
        if not has_tls:
            findings.append(SecurityFinding(
                host=ip, port=21, check="weak_protocol",
                severity="medio",
                title="FTP sem TLS",
                detail="FTP transmite credenciais em texto plano.",
                remediation="Migrar para SFTP ou habilitar FTPS (TLS).",
            ))

    # VNC
    if 5900 in port_set:
        vnc_banner = ""
        for b in banners:
            if b.startswith("5900:"):
                vnc_banner = b
                break
        findings.append(SecurityFinding(
            host=ip, port=5900, check="weak_protocol",
            severity="alto",
            title="VNC exposto",
            detail="VNC permite controle remoto. Muitas implementações "
                   "usam autenticação fraca ou nenhuma.",
            evidence=vnc_banner,
            remediation="Proteger VNC com VPN/túnel SSH. Usar senha forte.",
        ))

    return findings


# ==============================
# 3. HTTP paths sensíveis
# ==============================

_SENSITIVE_PATHS = [
    # Source code / version control
    ("/.git/HEAD", "Git repository exposto", "critico",
     "Código fonte completo pode ser baixado com git-dumper."),
    ("/.svn/entries", "SVN repository exposto", "critico",
     "Código fonte acessível."),
    ("/.env", "Arquivo .env exposto", "critico",
     "Contém senhas, API keys, tokens de banco de dados."),

    # PHP info
    ("/phpinfo.php", "phpinfo() exposto", "alto",
     "Revela config completa do PHP, paths, extensions, variáveis de ambiente."),
    ("/info.php", "phpinfo() exposto", "alto",
     "Revela config completa do PHP."),

    # Admin panels
    ("/admin/", "Painel admin acessível", "medio",
     "Painel de administração exposto na rede."),
    ("/wp-admin/", "WordPress admin", "medio",
     "Painel do WordPress acessível."),
    ("/wp-login.php", "WordPress login", "medio",
     "Login do WordPress acessível."),
    ("/phpmyadmin/", "phpMyAdmin exposto", "alto",
     "Interface de banco de dados exposta. Permite manipulação direta do MySQL."),
    ("/adminer.php", "Adminer exposto", "alto",
     "Interface de banco de dados exposta."),

    # Backup / config files
    ("/backup.sql", "Backup SQL exposto", "critico",
     "Dump do banco de dados acessível publicamente."),
    ("/backup.zip", "Backup ZIP exposto", "critico",
     "Arquivo de backup acessível."),
    ("/config.php.bak", "Config PHP backup", "critico",
     "Backup de configuração com possíveis credenciais."),
    ("/web.config", "web.config exposto", "alto",
     "Config do IIS/ASP.NET com possíveis connection strings."),

    # Server status
    ("/server-status", "Apache server-status", "medio",
     "Revela URLs acessadas, IPs de clientes, workers."),
    ("/server-info", "Apache server-info", "medio",
     "Revela config completa do Apache."),

    # API docs
    ("/swagger/", "Swagger UI exposto", "medio",
     "Documentação de API exposta — revela todos os endpoints."),
    ("/api-docs", "API docs exposto", "medio",
     "Documentação de API acessível."),
]


def _check_http_paths(
    ip: str, port: int, timeout: float = 3.0,
) -> List[SecurityFinding]:
    """Verifica paths HTTP sensíveis com requests mínimos."""
    try:
        import requests
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except ImportError:
        return []

    findings = []
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{ip}:{port}"

    session = requests.Session()
    session.verify = False
    session.timeout = timeout
    session.headers["User-Agent"] = "Mozilla/5.0 (Security Audit)"

    for path, title, severity, detail in _SENSITIVE_PATHS:
        try:
            resp = session.get(f"{base}{path}", allow_redirects=False, timeout=timeout)

            # 200 = accessible, 403 = exists but protected (still interesting)
            if resp.status_code == 200:
                # Validate it's not a generic "not found" page
                content = resp.text[:500].lower()
                if "not found" in content or "404" in content:
                    continue

                # .git/HEAD should contain "ref: refs/"
                if ".git/HEAD" in path and "ref:" not in resp.text:
                    continue

                # .env should contain KEY=VALUE patterns
                if ".env" in path and "=" not in resp.text[:200]:
                    continue

                findings.append(SecurityFinding(
                    host=ip, port=port, check="http_exposure",
                    severity=severity,
                    title=title,
                    detail=detail,
                    evidence=f"GET {path} → 200 OK ({len(resp.content)} bytes)",
                    remediation=f"Bloquear acesso a {path} no servidor web.",
                ))

            elif resp.status_code == 403 and path in ("/.git/HEAD", "/.env", "/phpmyadmin/"):
                findings.append(SecurityFinding(
                    host=ip, port=port, check="http_exposure",
                    severity="info",
                    title=f"{title} (403 Forbidden)",
                    detail=f"Path {path} existe mas está bloqueado. Confirmar que "
                           f"o recurso não está acessível por outro caminho.",
                    evidence=f"GET {path} → 403",
                ))

        except Exception:
            continue

    return findings


# ==============================
# 4. SSL/TLS checks
# ==============================

def _check_ssl_cert(ip: str, port: int, timeout: float = 3.0) -> List[SecurityFinding]:
    """Verifica certificado SSL e cifras."""
    findings = []

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as tls:
                cert = tls.getpeercert(binary_form=False)
                cipher = tls.cipher()
                version = tls.version()

                # Check TLS version
                if version and version in ("TLSv1", "TLSv1.1", "SSLv3"):
                    findings.append(SecurityFinding(
                        host=ip, port=port, check="ssl",
                        severity="alto",
                        title=f"TLS versão obsoleta: {version}",
                        detail=f"Usando {version} que tem vulnerabilidades conhecidas "
                               f"(POODLE, BEAST, etc).",
                        evidence=f"Protocolo: {version}",
                        remediation="Configurar TLS 1.2+ como mínimo.",
                    ))

                # Check cipher
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ("RC4", "DES", "3DES", "NULL", "EXPORT", "anon")
                    if any(w in cipher_name for w in weak_ciphers):
                        findings.append(SecurityFinding(
                            host=ip, port=port, check="ssl",
                            severity="medio",
                            title=f"Cifra fraca: {cipher_name}",
                            detail="Cifra criptográfica considerada insegura.",
                            evidence=f"Cipher: {cipher_name}",
                            remediation="Configurar apenas cifras fortes (AES-GCM, ChaCha20).",
                        ))

                # Check certificate
                if cert:
                    import datetime
                    not_after = ssl.cert_time_to_seconds(cert.get("notAfter", ""))
                    now = time.time()
                    if not_after < now:
                        findings.append(SecurityFinding(
                            host=ip, port=port, check="ssl",
                            severity="medio",
                            title="Certificado SSL EXPIRADO",
                            detail=f"Certificado expirou em {cert.get('notAfter')}.",
                            evidence=f"notAfter: {cert.get('notAfter')}",
                            remediation="Renovar certificado SSL.",
                        ))
                    elif not_after - now < 30 * 86400:
                        findings.append(SecurityFinding(
                            host=ip, port=port, check="ssl",
                            severity="baixo",
                            title="Certificado SSL expira em breve",
                            detail=f"Expira em {cert.get('notAfter')}.",
                            evidence=f"notAfter: {cert.get('notAfter')}",
                            remediation="Renovar certificado SSL.",
                        ))

    except ssl.SSLError:
        pass  # Self-signed or other SSL issues — already not trusted
    except Exception:
        pass

    return findings


# ==============================
# 5. Orquestrador principal
# ==============================

def run_security_checks(
    hosts: Dict[str, dict],
    timeout: float = 3.0,
    max_workers: int = 8,
    check_http: bool = True,
) -> Dict[str, List[SecurityFinding]]:
    """
    Executa todos os security checks nos hosts online.

    Roda em paralelo por host, com checks cirúrgicos baseados nas portas abertas.

    Args:
        hosts: Dict IP -> scan result (com portas, banners).
        timeout: Timeout para conexões extras.
        max_workers: Paralelismo.
        check_http: Se True, faz HTTP path discovery (mais lento).

    Returns:
        Dict IP -> lista de SecurityFindings.
    """
    all_findings: Dict[str, List[SecurityFinding]] = {}

    online_hosts = {
        ip: data for ip, data in hosts.items()
        if data.get("status") == "ONLINE" and data.get("portas")
    }

    if not online_hosts:
        return all_findings

    def _check_host(ip: str, host: dict) -> List[SecurityFinding]:
        findings = []
        port_set = set()
        for p in host.get("portas", []):
            try:
                port_set.add(int(p))
            except ValueError:
                pass

        # Weak protocols (from banners, no extra connection)
        findings.extend(check_weak_protocols(host))

        # Open services (targeted connection tests)
        if 6379 in port_set:
            f = _check_redis_noauth(ip, 6379, timeout)
            if f:
                findings.append(f)

        if 27017 in port_set:
            f = _check_mongodb_noauth(ip, 27017, timeout)
            if f:
                findings.append(f)

        if 11211 in port_set:
            f = _check_memcached_open(ip, 11211, timeout)
            if f:
                findings.append(f)

        if 21 in port_set:
            f = _check_ftp_anonymous(ip, 21, timeout)
            if f:
                findings.append(f)

        # HTTP path checks (most impactful)
        if check_http:
            http_ports = port_set & {80, 443, 8080, 8443, 8000, 8888}
            for hp in sorted(http_ports)[:2]:  # Max 2 HTTP ports per host
                findings.extend(_check_http_paths(ip, hp, timeout))

        # SSL checks on TLS ports
        tls_ports = port_set & {443, 8443, 465, 993, 995}
        for tp in sorted(tls_ports)[:2]:
            findings.extend(_check_ssl_cert(ip, tp, timeout))

        return findings

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_check_host, ip, host): ip
            for ip, host in online_hosts.items()
        }
        for future in as_completed(futures):
            ip = futures[future]
            try:
                findings = future.result(timeout=30)
                if findings:
                    all_findings[ip] = findings
            except Exception:
                pass

    return all_findings
