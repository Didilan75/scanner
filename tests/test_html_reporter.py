from pathlib import Path
from unittest.mock import patch

from port_scanner import PortResult
from cve import CVEResult
from html_reporter import generate_html, save_and_open


def _scan_results(kev: bool = False) -> list[dict]:
    port = PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache 2.4.41', cpes=['cpe:/a:apache:http_server:2.4.41'],
    )
    cve = CVEResult(
        cve_id='CVE-2021-41773', cvss_score=9.8,
        severity='CRITICAL', description='Path traversal', kev=kev,
    )
    return [{'ip': '192.168.1.1', 'ports': [port], 'cve_map': {'cpe:/a:apache:http_server:2.4.41': [cve]}}]


def test_generate_html_contains_host_ip():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results())
    assert '192.168.1.1' in html


def test_generate_html_contains_cve_id():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results())
    assert 'CVE-2021-41773' in html


def test_generate_html_kev_flag_true_in_data():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results(kev=True))
    assert '"kev": true' in html


def test_generate_html_kev_flag_false_in_data():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results(kev=False))
    assert '"kev": false' in html


def test_save_and_open_writes_file(tmp_path):
    out = tmp_path / 'report.html'
    with patch('html_reporter.webbrowser.open', return_value=True):
        save_and_open('<html>test</html>', out)
    assert out.exists()
    assert '<html>test</html>' in out.read_text(encoding='utf-8')


def test_generate_html_exploit_flag_true_in_data():
    port = PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache 2.4.41', cpes=['cpe:/a:apache:http_server:2.4.41'],
    )
    cve = CVEResult(
        cve_id='CVE-2021-41773', cvss_score=9.8,
        severity='CRITICAL', description='Path traversal', exploit_available=True,
    )
    scan_results = [{'ip': '192.168.1.1', 'ports': [port], 'cve_map': {'cpe:/a:apache:http_server:2.4.41': [cve]}}]
    html = generate_html('192.168.1.0/24', '2026-07-05T14:32:00Z', scan_results)
    assert '"exploit_available": true' in html


def test_generate_html_exploit_flag_false_in_data():
    port = PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache 2.4.41', cpes=['cpe:/a:apache:http_server:2.4.41'],
    )
    cve = CVEResult(
        cve_id='CVE-2021-41773', cvss_score=9.8,
        severity='CRITICAL', description='Path traversal', exploit_available=False,
    )
    scan_results = [{'ip': '192.168.1.1', 'ports': [port], 'cve_map': {'cpe:/a:apache:http_server:2.4.41': [cve]}}]
    html = generate_html('192.168.1.0/24', '2026-07-05T14:32:00Z', scan_results)
    assert '"exploit_available": false' in html
