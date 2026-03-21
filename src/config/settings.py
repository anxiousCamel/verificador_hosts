"""
# src/config/settings.py — Auto-configuração conservadora do scanner

## Descrição
Define presets de configuração por modo (leve/completo/auto) e aplica
overrides de variáveis de ambiente com limites rígidos (clamps).

Filosofia:
- O modo define **features** (resolver hostname, checar CVEs, etc.)
- O paralelismo é sempre conservador para não travar a máquina
- Clamps duros impedem valores perigosos vindos de ENV
- A governança adaptativa (core/governor.py) pode reduzir ainda mais em runtime

## Saída
Dict consumido por core/batch_scanner.py com todos os parâmetros operacionais:
- max_workers_hosts, max_workers_portas, timeout_socket
- max_sockets, batch_size
- resolve_hostname, tcp_only, skip_cve, skip_nvd_update
- mode, adaptive

## Variáveis de ambiente (opcionais, sempre com clamps)
- `VH_MODE`: "leve" | "completo" | "auto" (padrão: "auto")
- `VH_ASK_MODE`: "1" para perguntar o modo interativamente
- `VH_MAX_HOSTS_WORKERS`: 4-12
- `VH_MAX_PORTS_WORKERS`: 2-6
- `VH_TIMEOUT_SOCKET`: 1.5-5.0 segundos
- `VH_MAX_SOCKETS`: 64-160 (depende do SO)
- `VH_BATCH_SIZE`: 6-16
- `VH_RESOLVE_HOSTNAME`, `VH_TCP_ONLY`, `VH_SKIP_CVE`, `VH_SKIP_NVD_UPDATE`: 0/1

Camada: config (sem dependências de projeto)
"""

from __future__ import annotations

import os
import platform
from typing import Dict


# ============================
# Leitura de ENV com validação
# ============================

def _env_int(key: str, default: int, min_val: int, max_val: int) -> int:
    """Lê inteiro de ENV com clamp entre min_val e max_val."""
    try:
        value = int(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(min_val, min(max_val, value))


def _env_float(key: str, default: float, min_val: float, max_val: float) -> float:
    """Lê float de ENV com clamp entre min_val e max_val."""
    try:
        value = float(os.getenv(key, str(default)))
    except (TypeError, ValueError):
        value = default
    return max(min_val, min(max_val, value))


def _env_bool(key: str, default: bool) -> bool:
    """Lê booleano de ENV (aceita 1/true/yes/on)."""
    val = os.getenv(key)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")


def _is_windows() -> bool:
    """Detecta se o SO é Windows."""
    return platform.system().lower().startswith("win")


# ============================
# Limites rígidos (hard clamps)
# ============================

_LIMITS = {
    "hosts":       (4, 12),
    "ports":       (2, 6),
    "sockets_win": (64, 128),
    "sockets_nix": (64, 160),
    "batch":       (6, 16),
    "timeout":     (1.5, 5.0),
}


# ============================
# Presets por modo
# ============================

PRESET_ULTRA = {
    "hosts": 10,
    "ports": 4,
    "timeout": 1.0,
    "batch": 16,
    "resolve_hostname": False,
    "tcp_only": True,
    "skip_cve": True,
    "skip_nvd_update": True,
    "adaptive": True,
    "fast_ports": True,       # Use FAST_SCAN_PORTS (15 ports vs 40+)
    "ping_timeout_ms": 500,   # Aggressive ping timeout (LAN only)
    "discovery_workers": 50,  # High parallelism for alive discovery
}

PRESET_LIGHT = {
    "hosts": 8,               # Same parallelism as completo (was 6 = slower!)
    "ports": 4,               # Same as completo (was 3 = slower!)
    "timeout": 1.5,           # Reduced from 2.0 (LAN doesn't need 2s)
    "batch": 12,
    "resolve_hostname": False,
    "tcp_only": True,
    "skip_cve": False,         # CVEs ARE checked (was True = lost info!)
    "skip_nvd_update": False,
    "adaptive": True,
    "fast_ports": True,        # 15 ports vs 40+ (THIS is what makes it "light")
    "ping_timeout_ms": 800,
    "discovery_workers": 40,
}

PRESET_COMPLETE = {
    "hosts": 8,
    "ports": 4,
    "timeout": 2.5,           # Reduced from 3.0
    "batch": 12,              # Increased from 10
    "resolve_hostname": True,
    "tcp_only": False,
    "skip_cve": False,
    "skip_nvd_update": False,
    "adaptive": True,
    "fast_ports": False,
    "ping_timeout_ms": 1000,
    "discovery_workers": 30,
}


def _select_preset(mode: str, is_win: bool) -> Dict:
    """
    Seleciona o preset base conforme modo e SO.

    No modo "auto", Windows usa preset leve, Linux usa completo.

    Args:
        mode: "leve", "completo", "ultra" ou "auto".
        is_win: True se Windows.

    Returns:
        Cópia do preset selecionado.
    """
    if mode == "ultra":
        return PRESET_ULTRA.copy()
    if mode == "leve":
        return PRESET_LIGHT.copy()
    if mode == "completo":
        return PRESET_COMPLETE.copy()
    return PRESET_LIGHT.copy() if is_win else PRESET_COMPLETE.copy()


# ============================
# Interação com usuário
# ============================

def _ask_mode_interactive(default: str) -> str:
    """
    Pergunta ao usuário qual modo usar, se VH_ASK_MODE=1.

    Args:
        default: Modo padrão se o usuário não escolher.

    Returns:
        Modo escolhido.
    """
    if not _env_bool("VH_ASK_MODE", True):
        return default

    try:
        print(f"[config] Modo atual: {default}.")
        answer = input("[config] Escolha o modo [auto|leve|completo|ultra] (Enter mantém): ").strip().lower()
        return answer if answer in ("auto", "leve", "completo", "ultra") else default
    except Exception:
        return default


# ============================
# Aplicação de clamps e overrides
# ============================

def _apply_clamps(preset: Dict, is_win: bool) -> Dict:
    """
    Aplica limites rígidos ao preset e calcula max_sockets.

    Garante que hosts * ports não exceda 85% de max_sockets
    (evita exaustão de file descriptors).
    """
    hmin, hmax = _LIMITS["hosts"]
    pmin, pmax = _LIMITS["ports"]
    bmin, bmax = _LIMITS["batch"]
    tmin, tmax = _LIMITS["timeout"]

    hosts = max(hmin, min(hmax, int(preset["hosts"])))
    ports = max(pmin, min(pmax, int(preset["ports"])))
    batch = max(bmin, min(bmax, int(preset["batch"])))
    timeout = _env_float("VH_TIMEOUT_SOCKET", float(preset["timeout"]), tmin, tmax)

    if is_win:
        smin, smax = _LIMITS["sockets_win"]
    else:
        smin, smax = _LIMITS["sockets_nix"]
    max_sockets = _env_int("VH_MAX_SOCKETS", smax, smin, smax)

    safe_limit = int(max_sockets * 0.85)
    while hosts * ports > safe_limit and ports > pmin:
        ports -= 1
    while hosts * ports > safe_limit and hosts > hmin:
        hosts -= 1

    preset.update({
        "hosts": hosts,
        "ports": ports,
        "timeout": timeout,
        "batch": batch,
        "max_sockets": max_sockets,
    })
    return preset


def _apply_env_overrides(preset: Dict, is_win: bool) -> Dict:
    """Aplica overrides de variáveis de ambiente ao preset."""
    hmin, hmax = _LIMITS["hosts"]
    pmin, pmax = _LIMITS["ports"]
    bmin, bmax = _LIMITS["batch"]
    tmin, tmax = _LIMITS["timeout"]

    preset["hosts"] = _env_int("VH_MAX_HOSTS_WORKERS", preset["hosts"], hmin, hmax)
    preset["ports"] = _env_int("VH_MAX_PORTS_WORKERS", preset["ports"], pmin, pmax)
    preset["batch"] = _env_int("VH_BATCH_SIZE", preset["batch"], bmin, bmax)
    preset["timeout"] = _env_float("VH_TIMEOUT_SOCKET", preset["timeout"], tmin, tmax)

    preset["resolve_hostname"] = _env_bool("VH_RESOLVE_HOSTNAME", preset["resolve_hostname"])
    preset["tcp_only"] = _env_bool("VH_TCP_ONLY", preset["tcp_only"])
    preset["skip_cve"] = _env_bool("VH_SKIP_CVE", preset["skip_cve"])
    preset["skip_nvd_update"] = _env_bool("VH_SKIP_NVD_UPDATE", preset["skip_nvd_update"])

    return _apply_clamps(preset, is_win)


# ============================
# API pública
# ============================

def auto_configurar() -> Dict[str, object]:
    """
    Configura automaticamente o scanner baseado em modo, SO e variáveis de ambiente.

    Fluxo:
    1. Determina modo (ENV ou interativo)
    2. Seleciona preset base
    3. Aplica clamps por SO
    4. Aplica overrides de ENV (com re-clamp)
    5. Loga configuração efetiva

    Returns:
        Dicionário com todos os parâmetros operacionais:
        - max_workers_hosts (int): Workers para scan de hosts em paralelo
        - max_workers_portas (int): Workers para port scan por host
        - timeout_socket (float): Timeout de conexão em segundos
        - max_sockets (int): Limite global de sockets simultâneos
        - batch_size (int): Tamanho do lote de IPs
        - resolve_hostname (bool): Resolver DNS reverso
        - tcp_only (bool): Usar apenas TCP (sem ICMP avançado)
        - skip_cve (bool): Pular verificação de CVEs
        - skip_nvd_update (bool): Pular atualização da base NVD
        - mode (str): Modo efetivo usado
        - adaptive (bool): Governança adaptativa habilitada
    """
    is_win = _is_windows()

    mode = (os.getenv("VH_MODE") or "auto").strip().lower()
    if mode not in ("auto", "leve", "completo", "ultra"):
        mode = "auto"
    mode = _ask_mode_interactive(mode)

    preset = _select_preset(mode, is_win)
    preset = _apply_clamps(preset, is_win)
    preset = _apply_env_overrides(preset, is_win)

    estimated_sockets = preset["hosts"] * preset["ports"]
    print(
        f"[config] modo={mode} | hosts={preset['hosts']} | portas={preset['ports']} | "
        f"timeout={preset['timeout']}s | batch={preset['batch']} | "
        f"max_sockets={preset['max_sockets']} | "
        f"resolve_hostname={int(preset['resolve_hostname'])} | "
        f"tcp_only={int(preset['tcp_only'])} | "
        f"skip_cve={int(preset['skip_cve'])} | "
        f"skip_nvd_update={int(preset['skip_nvd_update'])} | "
        f"est_sockets={estimated_sockets}"
    )

    return {
        "max_workers_hosts": int(preset["hosts"]),
        "max_workers_portas": int(preset["ports"]),
        "timeout_socket": float(preset["timeout"]),
        "max_sockets": int(preset["max_sockets"]),
        "batch_size": int(preset["batch"]),
        "resolve_hostname": bool(preset["resolve_hostname"]),
        "tcp_only": bool(preset["tcp_only"]),
        "skip_cve": bool(preset["skip_cve"]),
        "skip_nvd_update": bool(preset["skip_nvd_update"]),
        "mode": mode,
        "adaptive": bool(preset.get("adaptive", True)),
        "fast_ports": bool(preset.get("fast_ports", False)),
        "ping_timeout_ms": int(preset.get("ping_timeout_ms", 1000)),
        "discovery_workers": int(preset.get("discovery_workers", 40)),
    }
