"""
# cache.py — Cache inteligente de resultados de scan

## Descrição
Persiste resultados de varredura em arquivo JSON com TTL por entrada.
Em re-execuções na mesma rede, hosts já varridos recentemente são
reutilizados do cache, economizando tempo de rede.

## Comportamento
- Cada entrada tem timestamp de quando foi varrida
- Entradas expiradas (mais velhas que `ttl_minutes`) são ignoradas
- Hosts OFFLINE nunca são cacheados (podem ter voltado)
- O cache é atômico: escreve em arquivo temporário + rename

## Formato do arquivo
```json
{
  "10.101.6.1": {
    "timestamp": "2024-01-15T14:30:00",
    "data": { ...resultado do scan... }
  }
}
```

## Autor
Luiz
"""

from __future__ import annotations

import os
import json
from datetime import datetime, timedelta
from typing import Dict, Optional


# TTL padrão: 30 minutos (configurável via ENV)
DEFAULT_TTL_MINUTES = int(os.environ.get("VH_CACHE_TTL_MINUTES", "30"))
CACHE_FILE = os.environ.get("VH_CACHE_FILE", ".scan_cache.json")


def _load_raw_cache(filepath: str) -> dict:
    """Carrega o arquivo de cache do disco. Retorna dict vazio se falhar."""
    try:
        if os.path.exists(filepath):
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_raw_cache(filepath: str, data: dict) -> None:
    """
    Salva cache no disco de forma atômica (write + rename).

    Evita corrupção em caso de crash ou Ctrl+C durante a escrita.
    """
    tmp_path = filepath + ".tmp"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, filepath)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


class ScanCache:
    """
    Cache de resultados de scan com TTL por entrada.

    Uso típico:
    ```python
    cache = ScanCache(ttl_minutes=30)
    cached = cache.get("10.0.0.1")
    if cached:
        # Usa resultado do cache
    else:
        result = scan_host(...)
        cache.put("10.0.0.1", result)
    cache.save()
    ```

    Args:
        filepath: Caminho do arquivo de cache JSON.
        ttl_minutes: Tempo de vida de cada entrada em minutos.
    """

    def __init__(self, filepath: str = CACHE_FILE, ttl_minutes: int = DEFAULT_TTL_MINUTES):
        self._filepath = filepath
        self._ttl = timedelta(minutes=ttl_minutes)
        self._data = _load_raw_cache(filepath)
        self._dirty = False

    def get(self, ip: str) -> Optional[dict]:
        """
        Busca resultado no cache para um IP.

        Retorna None se:
        - IP não está no cache
        - Entrada expirou (mais velha que TTL)
        - Entrada era de host OFFLINE (pode ter voltado)

        Args:
            ip: Endereço IP.

        Returns:
            Dicionário de resultado do scan ou None.
        """
        entry = self._data.get(ip)
        if not entry:
            return None

        try:
            ts = datetime.fromisoformat(entry["timestamp"])
        except (KeyError, ValueError):
            return None

        # Expirou?
        if datetime.now() - ts > self._ttl:
            return None

        result = entry.get("data", {})

        # Não reutiliza hosts OFFLINE (podem ter voltado)
        if result.get("status") != "ONLINE":
            return None

        return result

    def put(self, ip: str, result: dict) -> None:
        """
        Armazena resultado de scan no cache.

        Apenas hosts ONLINE são cacheados — hosts OFFLINE são voláteis
        e devem ser re-verificados.

        Args:
            ip: Endereço IP.
            result: Dicionário de resultado do scan_host.
        """
        if result.get("status") != "ONLINE":
            return

        self._data[ip] = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "data": result,
        }
        self._dirty = True

    def save(self) -> None:
        """Persiste cache no disco (somente se houve mudanças)."""
        if self._dirty:
            _save_raw_cache(self._filepath, self._data)
            self._dirty = False

    @property
    def stats(self) -> Dict[str, int]:
        """Retorna estatísticas do cache: total de entradas e válidas."""
        now = datetime.now()
        total = len(self._data)
        valid = 0
        for entry in self._data.values():
            try:
                ts = datetime.fromisoformat(entry["timestamp"])
                if now - ts <= self._ttl and entry.get("data", {}).get("status") == "ONLINE":
                    valid += 1
            except (KeyError, ValueError):
                pass
        return {"total": total, "valid": valid}

    def clear(self) -> None:
        """Limpa todo o cache."""
        self._data = {}
        self._dirty = True
