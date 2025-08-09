"""
# config.py (Conservador)

## Ideia
- Modo define **features** (leve vs completo), não agressividade.
- Paralelismo sempre conservador para não travar (independe de CPU/RAM).
- Só reduz quando necessário (governança adaptativa fica no __main__.py).
- ENV podem sobrescrever, mas com *clamps* duros.

## Saída (dict) consumida por __main__.py e scan.py
{
  "max_workers_hosts": int,   # conservador
  "max_workers_portas": int,  # conservador
  "timeout_socket": float,
  "max_sockets": int,         # baixo para evitar saturar Windows
  "batch_size": int,          # pequeno e previsível
  "resolve_hostname": bool,   # leve=False, completo=True
  "tcp_only": bool,           # leve=True,  completo=False
  "skip_cve": bool,           # leve=True,  completo=False
  "skip_nvd_update": bool,    # leve=True,  completo=False
  "mode": "leve"|"completo"|"auto",
  "adaptive": bool            # True => __main__ pode reduzir mais se precisar
}

## ENV (opcionais; sempre respeitados com clamps)
- VH_MODE: "leve"|"completo"|"auto" (default: auto)
- VH_ASK_MODE: 0|1 (default: 0) se 1 e TTY, pergunta o modo
- VH_MAX_HOSTS_WORKERS, VH_MAX_PORTS_WORKERS, VH_TIMEOUT_SOCKET
- VH_MAX_SOCKETS, VH_BATCH_SIZE
- VH_RESOLVE_HOSTNAME, VH_TCP_ONLY, VH_SKIP_CVE, VH_SKIP_NVD_UPDATE
"""

from __future__ import annotations

import os
import sys
import platform
from typing import Dict

# ============================
# Helpers simples
# ============================

def _get_int(env: str, default: int, min_v: int, max_v: int) -> int:
    try:
        v = int(os.getenv(env, str(default)))
    except (TypeError, ValueError):
        v = default
    return max(min_v, min(max_v, v))

def _get_float(env: str, default: float, min_v: float, max_v: float) -> float:
    try:
        v = float(os.getenv(env, str(default)))
    except (TypeError, ValueError):
        v = default
    return max(min_v, min(max_v, v))

def _get_bool(env: str, default: bool) -> bool:
    val = os.getenv(env)
    if val is None:
        return default
    return str(val).strip().lower() in ("1", "true", "yes", "on")

def _isatty() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False

def _is_windows() -> bool:
    return platform.system().lower().startswith("win")


# ============================
# Presets CONSERVADORES
# ============================

# Limites duros (não ultrapassar)
HARD_MAX_HOSTS   = 12   # nunca mais que isso, mesmo “NASA”
HARD_MAX_PORTS   = 6
HARD_MAX_SOCKETS_WIN = 128
HARD_MAX_SOCKETS_NIX = 160
HARD_MAX_BATCH   = 16

HARD_MIN_HOSTS   = 4
HARD_MIN_PORTS   = 2
HARD_MIN_SOCKETS = 64
HARD_MIN_BATCH   = 6

# Presets por modo (conservadores)
PRESET_LEVE = {
    "hosts": 6,
    "portas": 3,
    "timeout": 2.0,
    "batch": 8,
    "resolve_hostname": False,
    "tcp_only": True,
    "skip_cve": True,
    "skip_nvd_update": True,
    "adaptive": True,  # pode reduzir ainda mais se necessário
}

PRESET_COMPLETO = {
    "hosts": 8,
    "portas": 4,
    "timeout": 3.0,
    "batch": 10,
    "resolve_hostname": True,
    "tcp_only": False,
    "skip_cve": False,
    "skip_nvd_update": False,
    "adaptive": True,  # pode reduzir ainda mais se necessário
}

# Auto escolhe o preset, mas SEM aumentar a agressividade
def _preset_auto(is_win: bool) -> Dict:
    # No Windows: tende ao leve por padrão (para evitar travas)
    base = PRESET_LEVE.copy() if is_win else PRESET_COMPLETO.copy()
    return base


# ============================
# Perguntar modo (opcional)
# ============================

def _ask_mode(default_mode: str) -> str:
    # passa a perguntar por padrão
    ask = _get_bool("VH_ASK_MODE", True)

    if not ask:
        return default_mode

    try:
        # pergunta SEM depender de TTY; se der erro de input, mantém default
        print(f"[config] Modo atual: {default_mode}.")
        ans = input("[config] Escolha o modo [auto|leve|completo] (Enter mantém): ").strip().lower()
        return ans if ans in ("auto", "leve", "completo") else default_mode
    except Exception:
        return default_mode


# ============================
# Clamps e max_sockets por OS
# ============================

def _apply_clamps(p: Dict, is_win: bool) -> Dict:
    hosts  = max(HARD_MIN_HOSTS, min(HARD_MAX_HOSTS, int(p["hosts"])))
    portas = max(HARD_MIN_PORTS, min(HARD_MAX_PORTS, int(p["portas"])))
    batch  = max(HARD_MIN_BATCH, min(HARD_MAX_BATCH, int(p["batch"])))
    timeout = _get_float("VH_TIMEOUT_SOCKET", float(p["timeout"]), 1.5, 5.0)

    # max_sockets conservador por OS
    if is_win:
        max_sockets = _get_int("VH_MAX_SOCKETS", HARD_MAX_SOCKETS_WIN, HARD_MIN_SOCKETS, HARD_MAX_SOCKETS_WIN)
    else:
        max_sockets = _get_int("VH_MAX_SOCKETS", HARD_MAX_SOCKETS_NIX, HARD_MIN_SOCKETS, HARD_MAX_SOCKETS_NIX)

    # Não permitir hosts*portas acima de ~85% do max_sockets
    alvo = int(max_sockets * 0.85)
    while hosts * portas > alvo and portas > HARD_MIN_PORTS:
        portas -= 1
    while hosts * portas > alvo and hosts > HARD_MIN_HOSTS:
        hosts -= 1

    p.update({
        "hosts": hosts,
        "portas": portas,
        "timeout": timeout,
        "batch": batch,
        "max_sockets": max_sockets,
    })
    return p


# ============================
# Overrides por ENV (respeitando clamps)
# ============================

def _overrides(p: Dict, is_win: bool) -> Dict:
    p["hosts"]  = _get_int("VH_MAX_HOSTS_WORKERS", p["hosts"], HARD_MIN_HOSTS, HARD_MAX_HOSTS)
    p["portas"] = _get_int("VH_MAX_PORTS_WORKERS", p["portas"], HARD_MIN_PORTS, HARD_MAX_PORTS)
    p["batch"]  = _get_int("VH_BATCH_SIZE", p["batch"], HARD_MIN_BATCH, HARD_MAX_BATCH)
    p["timeout"] = _get_float("VH_TIMEOUT_SOCKET", p["timeout"], 1.5, 5.0)

    # Flags de features (podem ser forçadas, mas não mexem no paralelismo base)
    p["resolve_hostname"] = _get_bool("VH_RESOLVE_HOSTNAME", p["resolve_hostname"])
    p["tcp_only"]         = _get_bool("VH_TCP_ONLY", p["tcp_only"])
    p["skip_cve"]         = _get_bool("VH_SKIP_CVE", p["skip_cve"])
    p["skip_nvd_update"]  = _get_bool("VH_SKIP_NVD_UPDATE", p["skip_nvd_update"])

    # Reaplicar clamps (garantia)
    return _apply_clamps(p, is_win)


# ============================
# API
# ============================

def auto_configurar() -> Dict[str, object]:
    is_win = _is_windows()

    modo = (os.getenv("VH_MODE") or "auto").strip().lower()
    if modo not in ("auto", "leve", "completo"):
        modo = "auto"
    modo = _ask_mode(modo)

    if modo == "leve":
        preset = PRESET_LEVE.copy()
    elif modo == "completo":
        preset = PRESET_COMPLETO.copy()
    else:  # auto
        preset = _preset_auto(is_win)

    # Clamps conservadores e max_sockets por OS
    preset = _apply_clamps(preset, is_win)
    # Overrides de ENV (com clamps)
    preset = _overrides(preset, is_win)

    # Log informativo
    sockets_estimados = preset["hosts"] * preset["portas"]
    print(
        "[config] "
        f"modo={modo} | hosts={preset['hosts']} | portas={preset['portas']} | "
        f"timeout={preset['timeout']}s | batch={preset['batch']} | "
        f"max_sockets={preset['max_sockets']} | "
        f"resolve_hostname={int(preset['resolve_hostname'])} | "
        f"tcp_only={int(preset['tcp_only'])} | "
        f"skip_cve={int(preset['skip_cve'])} | "
        f"skip_nvd_update={int(preset['skip_nvd_update'])} | "
        f"est_sockets={sockets_estimados}"
    )

    return {
        "max_workers_hosts": int(preset["hosts"]),
        "max_workers_portas": int(preset["portas"]),
        "timeout_socket": float(preset["timeout"]),

        "max_sockets": int(preset["max_sockets"]),
        "batch_size": int(preset["batch"]),

        "resolve_hostname": bool(preset["resolve_hostname"]),
        "tcp_only": bool(preset["tcp_only"]),
        "skip_cve": bool(preset["skip_cve"]),
        "skip_nvd_update": bool(preset["skip_nvd_update"]),

        "mode": modo,
        "adaptive": bool(preset.get("adaptive", True)),
    }
