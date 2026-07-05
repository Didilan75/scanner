import json
import os
from unittest.mock import patch, MagicMock

import pytest

from port_scanner import PortResult
from cve import CVEResult

MOCK_PORTS = [
    PortResult(
        port=22, protocol='tcp', state='open', service='ssh',
        version='OpenSSH 7.9', cpes=['cpe:/a:openbsd:openssh:7.9'],
    ),
    PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache httpd 2.4.41', cpes=['cpe:/a:apache:http_server:2.4.41'],
    ),
]

MOCK_CVES = [
    CVEResult(
        cve_id='CVE-2023-38408', cvss_score=9.8,
        severity='CRITICAL', description='RCE via ssh-agent',
    ),
]


def _make_progress_mock():
    mock_progress = MagicMock()
    mock_ctx = MagicMock()
    mock_progress.return_value.__enter__ = MagicMock(return_value=mock_ctx)
    mock_progress.return_value.__exit__ = MagicMock(return_value=False)
    return mock_progress, mock_ctx


def test_main_runs_full_pipeline_without_output():
    import main as m
    mock_progress, mock_ctx = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()


def test_main_saves_json_output(tmp_path):
    import main as m
    output_file = str(tmp_path / 'report.json')
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--output', output_file]), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    assert os.path.exists(output_file)
    with open(output_file) as f:
        data = json.load(f)
    assert data['subnet'] == '192.168.1.0/24'
    assert len(data['hosts']) == 1
    assert data['hosts'][0]['ip'] == '192.168.1.1'


def test_main_exits_when_nmap_not_found():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=False), \
         pytest.raises(SystemExit) as exc_info:
        m.main()

    assert exc_info.value.code == 1


def test_main_exits_when_no_hosts_found():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=[]), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()


def test_main_exits_when_host_discovery_fails():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', side_effect=RuntimeError('nmap ping sweep failed')), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.make_progress', mock_progress), \
         pytest.raises(SystemExit) as exc_info:
        m.main()

    assert exc_info.value.code == 1


def test_main_skips_host_when_port_scan_fails():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1', '192.168.1.2']), \
         patch('main.scan_host', side_effect=[RuntimeError('scan failed'), MOCK_PORTS]), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()


def test_main_html_flag_generates_and_opens_dashboard():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--html']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress), \
         patch('main.generate_html', return_value='<html></html>') as mock_gen, \
         patch('main.save_and_open') as mock_open:
        m.main()

    mock_gen.assert_called_once()
    mock_open.assert_called_once()


def test_main_kev_file_flag_passed_to_load_kev_catalog():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--kev-file', 'my_kev.json']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()) as mock_kev, \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    mock_kev.assert_called_once_with(kev_file='my_kev.json')


def test_main_stamps_kev_on_matching_cves():
    import main as m
    mock_progress, _ = _make_progress_mock()
    stamped_flags = []

    def capture_print_host(ip, ports, cve_map):
        for cves in cve_map.values():
            stamped_flags.extend(c.kev for c in cves)

    kev_cve = CVEResult(
        cve_id='CVE-2023-38408', cvss_score=9.8,
        severity='CRITICAL', description='RCE',
    )

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=[kev_cve]), \
         patch('main.load_kev_catalog', return_value={'CVE-2023-38408'}), \
         patch('main.load_exploitdb_cves', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host', side_effect=capture_print_host), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    assert any(stamped_flags), 'Expected CVE-2023-38408 to be stamped kev=True'


def test_main_exploitdb_file_flag_passed_to_load_exploitdb_cves():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--exploitdb-file', 'my_exploits.csv']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value=set()) as mock_exploitdb, \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    mock_exploitdb.assert_called_once_with(exploitdb_file='my_exploits.csv')


def test_main_stamps_exploit_available_on_matching_cves():
    import main as m
    mock_progress, _ = _make_progress_mock()
    stamped_flags = []

    def capture_print_host(ip, ports, cve_map):
        for cves in cve_map.values():
            stamped_flags.extend(c.exploit_available for c in cves)

    exploit_cve = CVEResult(
        cve_id='CVE-2023-38408', cvss_score=9.8,
        severity='CRITICAL', description='RCE',
    )

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=[exploit_cve]), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.load_exploitdb_cves', return_value={'CVE-2023-38408'}), \
         patch('main.print_summary'), \
         patch('main.print_host', side_effect=capture_print_host), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    assert any(stamped_flags), 'Expected CVE-2023-38408 to be stamped exploit_available=True'
