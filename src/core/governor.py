"""
# src/core/governor.py — Governança adaptativa de varredura

## Descrição
AdaptiveGovernor monitora a duração e taxa de timeouts de cada lote e
ajusta dinamicamente os parâmetros de varredura (batch_size, host_workers,
port_workers, socket_timeout).

## Estratégia (conservadora com histerese)
- Reduz batch primeiro (menos disruptivo), depois hosts, depois portas
- Só aumenta após N lotes bons consecutivos
- Cooldown entre ajustes evita oscilação (efeito "sanfona")

## Critérios de redução
- Lote muito lento (>60s): reduz batch em 15%
- Lento + timeouts >10%: reduz batch em 15%
- 2+ lotes lentos seguidos: reduz hosts em 15%
- 3+ lotes lentos seguidos: reduz portas em 1

## Critérios de aumento
- 3 lotes bons consecutivos (<12s, <5% timeouts): +1 batch/hosts/portas

Camada: core (sem dependências de projeto)
"""

from __future__ import annotations

from typing import Tuple, Dict


class AdaptiveGovernor:
    """
    Ajusta dinamicamente os parâmetros de varredura com base na performance.

    Args:
        batch_size: Tamanho inicial do lote.
        host_workers: Workers de host iniciais.
        port_workers: Workers de porta iniciais.
        socket_timeout: Timeout inicial.
        batch_min/max, hosts_min/max, ports_min/max, timeout_min/max: Limites.
        slow_threshold_sec: Segundos para considerar lote "lento".
        very_slow_threshold_sec: Segundos para considerar lote "muito lento".
        timeout_ratio_high/moderate/low: Limiares de proporção de timeouts.
        fast_threshold_sec: Segundos para considerar lote "rápido".
        cooldown_batches: Lotes de cooldown após ajuste.
        good_batches_to_increase: Lotes bons para aumentar parâmetros.
        slow_batches_to_cut_hosts: Lotes lentos para reduzir hosts.
        slow_batches_to_cut_ports: Lotes lentos para reduzir portas.
    """

    def __init__(
        self,
        batch_size: int,
        host_workers: int,
        port_workers: int,
        socket_timeout: float,
        *,
        batch_min: int = 6, batch_max: int = 16,
        hosts_min: int = 4, hosts_max: int = 12,
        ports_min: int = 2, ports_max: int = 6,
        timeout_min: float = 1.5, timeout_max: float = 5.0,
        slow_threshold_sec: float = 40.0,
        very_slow_threshold_sec: float = 60.0,
        timeout_ratio_high: float = 0.30,
        timeout_ratio_moderate: float = 0.10,
        fast_threshold_sec: float = 12.0,
        timeout_ratio_low: float = 0.05,
        cooldown_batches: int = 2,
        good_batches_to_increase: int = 3,
        slow_batches_to_cut_hosts: int = 2,
        slow_batches_to_cut_ports: int = 3,
    ):
        self.batch = batch_size
        self.hosts = host_workers
        self.ports = port_workers
        self.timeout = socket_timeout

        self._limits = {
            "batch":   (batch_min, batch_max),
            "hosts":   (hosts_min, hosts_max),
            "ports":   (ports_min, ports_max),
            "timeout": (timeout_min, timeout_max),
        }

        self._slow_sec = slow_threshold_sec
        self._very_slow_sec = very_slow_threshold_sec
        self._timeout_high = timeout_ratio_high
        self._timeout_moderate = timeout_ratio_moderate
        self._fast_sec = fast_threshold_sec
        self._timeout_low = timeout_ratio_low

        self._cooldown_duration = cooldown_batches
        self._good_needed = good_batches_to_increase
        self._slow_for_hosts = slow_batches_to_cut_hosts
        self._slow_for_ports = slow_batches_to_cut_ports

        self._cooldown = 0
        self._consecutive_good = 0
        self._consecutive_slow = 0

    def _clamp(self) -> None:
        """Garante que todos os parâmetros estão dentro dos limites."""
        bmin, bmax = self._limits["batch"]
        hmin, hmax = self._limits["hosts"]
        pmin, pmax = self._limits["ports"]
        tmin, tmax = self._limits["timeout"]

        self.batch = max(bmin, min(bmax, int(self.batch)))
        self.hosts = max(hmin, min(hmax, int(self.hosts)))
        self.ports = max(pmin, min(pmax, int(self.ports)))
        self.timeout = max(tmin, min(tmax, float(self.timeout)))

    def _apply_reduction(self, attr: str, factor: float, msg: str) -> Tuple[bool, str]:
        """Aplica redução percentual a um atributo, respeitando limites."""
        current = getattr(self, attr)
        min_val = self._limits[attr][0]
        if current <= min_val:
            return False, ""
        new_val = max(min_val, int(current * factor))
        if attr == "ports":
            new_val = max(min_val, current - 1)
        setattr(self, attr, new_val)
        self._clamp()
        self._cooldown = self._cooldown_duration
        return True, msg.format(val=getattr(self, attr))

    def suggest(self, batch_duration: float, timeouts: int, completed: int) -> Tuple[bool, str]:
        """
        Analisa o lote e sugere ajustes nos parâmetros.

        Args:
            batch_duration: Duração do lote em segundos.
            timeouts: Número de hosts com timeout no lote.
            completed: Total de hosts processados no lote.

        Returns:
            Tupla (ajustou, mensagem). Se ajustou=False, nenhuma mudança.
        """
        if completed <= 0:
            return False, ""

        timeout_ratio = timeouts / max(1, completed)
        is_slow = batch_duration > self._slow_sec
        is_very_slow = batch_duration > self._very_slow_sec
        is_fast = batch_duration <= self._fast_sec
        low_timeouts = timeout_ratio <= self._timeout_low

        self._consecutive_slow = self._consecutive_slow + 1 if is_slow else 0

        if self._cooldown > 0:
            self._cooldown -= 1
            if is_fast and low_timeouts:
                self._consecutive_good += 1
            else:
                self._consecutive_good = 0
            return False, ""

        # --- REDUÇÃO ---

        if is_very_slow:
            ok, msg = self._apply_reduction(
                "batch", 0.85,
                "reduzindo batch->{val} (muito lento: " + f"{batch_duration:.1f}s)"
            )
            if ok:
                return True, msg

        if is_slow and timeout_ratio >= self._timeout_moderate:
            ok, msg = self._apply_reduction(
                "batch", 0.85,
                "reduzindo batch->{val} (lento + timeouts " + f"{timeout_ratio:.0%})"
            )
            if ok:
                return True, msg

        if is_slow and self._consecutive_slow >= self._slow_for_hosts:
            ok, msg = self._apply_reduction(
                "hosts", 0.85,
                "reduzindo hosts->{val} (lentos " + f"{self._consecutive_slow}x)"
            )
            if ok:
                return True, msg

        if is_slow and self._consecutive_slow >= self._slow_for_ports:
            ok, msg = self._apply_reduction(
                "ports", 1.0,
                "reduzindo portas->{val} (lentos " + f"{self._consecutive_slow}x)"
            )
            if ok:
                return True, msg

        if timeout_ratio >= self._timeout_moderate and self.timeout < self._limits["timeout"][1]:
            self.timeout = min(self._limits["timeout"][1], self.timeout + 0.5)
            self._clamp()
            self._cooldown = self._cooldown_duration
            return True, f"aumentando timeout->{self.timeout:.1f}s (timeouts {timeout_ratio:.0%})"

        # --- AUMENTO ---

        if is_fast and low_timeouts:
            self._consecutive_good += 1
        else:
            self._consecutive_good = 0

        if self._consecutive_good >= self._good_needed:
            for attr in ("batch", "hosts", "ports"):
                current = getattr(self, attr)
                max_val = self._limits[attr][1]
                if current < max_val:
                    setattr(self, attr, min(max_val, current + 1))
                    self._consecutive_good = 0
                    self._cooldown = self._cooldown_duration
                    self._clamp()
                    return True, (
                        f"aumentando {attr}->{getattr(self, attr)} "
                        f"(estável {self._good_needed} lotes)"
                    )

        return False, ""
