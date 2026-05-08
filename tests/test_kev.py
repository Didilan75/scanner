import json
import os
import time
import warnings
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests

from kev import load_kev_catalog, CISA_KEV_URL

SAMPLE_KEV = {
    'vulnerabilities': [
        {'cveID': 'CVE-2021-44228'},
        {'cveID': 'CVE-2021-41773'},
    ]
}


def test_load_from_local_file(tmp_path):
    kev_file = tmp_path / 'kev.json'
    kev_file.write_text(json.dumps(SAMPLE_KEV))
    result = load_kev_catalog(kev_file=str(kev_file))
    assert result == {'CVE-2021-44228', 'CVE-2021-41773'}


def test_local_file_not_found():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        result = load_kev_catalog(kev_file='/nonexistent/path.json')
    assert result == set()
    assert len(w) == 1


def test_local_file_invalid_json(tmp_path):
    kev_file = tmp_path / 'kev.json'
    kev_file.write_text('not valid json')
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        result = load_kev_catalog(kev_file=str(kev_file))
    assert result == set()
    assert len(w) == 1


def test_cache_hit(tmp_path):
    cache_file = tmp_path / 'kev_catalog.json'
    cache_file.write_text(json.dumps(SAMPLE_KEV))
    with patch('kev.requests.get') as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_not_called()
    assert 'CVE-2021-44228' in result


def test_cache_miss_downloads(tmp_path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = SAMPLE_KEV
    with patch('kev.requests.get', return_value=mock_resp) as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_called_once()
    assert 'CVE-2021-44228' in result
    assert (tmp_path / 'kev_catalog.json').exists()


def test_stale_cache_redownloads(tmp_path):
    cache_file = tmp_path / 'kev_catalog.json'
    cache_file.write_text(json.dumps(SAMPLE_KEV))
    old_time = time.time() - 90000  # > 24h ago
    os.utime(cache_file, (old_time, old_time))
    mock_resp = MagicMock()
    mock_resp.json.return_value = SAMPLE_KEV
    with patch('kev.requests.get', return_value=mock_resp) as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_called_once()
    assert 'CVE-2021-44228' in result


def test_download_failure_returns_empty(tmp_path):
    with patch('kev.requests.get', side_effect=requests.RequestException('timeout')):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            result = load_kev_catalog(cache_dir=tmp_path)
    assert result == set()
    assert len(w) == 1
