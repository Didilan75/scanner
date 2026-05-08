import json
import time
import warnings
from pathlib import Path

import requests

CISA_KEV_URL = (
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
)
_CACHE_MAX_AGE = 86400  # 24 hours in seconds


def _default_cache_path() -> Path:
    cache_dir = Path.home() / '.cache' / 'scanner'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / 'kev_catalog.json'


def _parse_catalog(data: dict) -> set[str]:
    return {v['cveID'] for v in data.get('vulnerabilities', [])}


def _load_json(path: Path) -> set[str]:
    with open(path, encoding='utf-8') as f:
        return _parse_catalog(json.load(f))


def _download_and_cache(cache_path: Path) -> set[str]:
    resp = requests.get(CISA_KEV_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    cache_path.write_text(json.dumps(data), encoding='utf-8')
    return _parse_catalog(data)


def load_kev_catalog(
    kev_file: str | None = None,
    cache_dir: Path | None = None,
) -> set[str]:
    """Return set of CVE IDs from the CISA KEV catalog.

    If kev_file is given, load from that path (no network call).
    Otherwise download from CISA with a 24h local cache.
    On any failure, warn and return empty set so the scan continues.
    """
    if kev_file is not None:
        try:
            return _load_json(Path(kev_file))
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            warnings.warn(
                f'KEV file load failed ({e}). Exploit status will not be shown.',
                stacklevel=2,
            )
            return set()

    cache_path = (cache_dir / 'kev_catalog.json') if cache_dir else _default_cache_path()

    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < _CACHE_MAX_AGE:
            try:
                return _load_json(cache_path)
            except (json.JSONDecodeError, KeyError):
                cache_path.unlink(missing_ok=True)

    try:
        return _download_and_cache(cache_path)
    except Exception as e:
        warnings.warn(
            f'KEV catalog download failed ({e}). Exploit status will not be shown.',
            stacklevel=2,
        )
        return set()
