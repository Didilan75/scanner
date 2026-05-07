import time
import requests
from dataclasses import dataclass


@dataclass
class CVEResult:
    cve_id: str
    cvss_score: float
    severity: str
    description: str


_last_request_times: list[float] = []
_RATE_WINDOW = 30.0


def _wait_for_rate_limit(api_key: str | None) -> None:
    global _last_request_times
    limit = 50 if api_key else 5
    now = time.time()
    _last_request_times = [t for t in _last_request_times if now - t < _RATE_WINDOW]
    if len(_last_request_times) >= limit:
        sleep_time = _RATE_WINDOW - (now - _last_request_times[0])
        if sleep_time > 0:
            time.sleep(sleep_time)
    _last_request_times.append(time.time())


def _extract_cvss(metrics: dict) -> tuple[float, str]:
    for key in ('cvssMetricV31', 'cvssMetricV30'):
        if key in metrics and metrics[key]:
            data = metrics[key][0].get('cvssData', {})
            return data.get('baseScore', 0.0), data.get('baseSeverity', 'NONE')
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        entry = metrics['cvssMetricV2'][0]
        score = entry.get('cvssData', {}).get('baseScore', 0.0)
        severity = entry.get('baseSeverity', 'NONE')
        return score, severity
    return 0.0, 'NONE'


def lookup_cves(cpe: str, api_key: str | None = None) -> list[CVEResult]:
    _wait_for_rate_limit(api_key)
    url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
    headers = {}
    if api_key:
        headers['apiKey'] = api_key
    params = {'cpeName': cpe, 'resultsPerPage': 10}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=10)
        if resp.status_code == 429:
            time.sleep(30)
            resp = requests.get(url, headers=headers, params=params, timeout=10)
        resp.raise_for_status()
    except requests.RequestException:
        return []

    results = []
    for vuln in resp.json().get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id', '')
        cvss_score, severity = _extract_cvss(cve.get('metrics', {}))
        descs = cve.get('descriptions', [])
        description = next((d['value'] for d in descs if d['lang'] == 'en'), '')[:200]
        results.append(CVEResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
        ))

    return sorted(results, key=lambda c: c.cvss_score, reverse=True)
