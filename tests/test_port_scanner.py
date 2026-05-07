from unittest.mock import MagicMock, patch
from port_scanner import scan_host, PortResult


def _port_data(service: str, product: str, version: str, cpe: str) -> dict:
    return {
        'state': 'open',
        'reason': 'syn-ack',
        'name': service,
        'product': product,
        'version': version,
        'extrainfo': '',
        'cpe': cpe,
    }


def _make_mock_scanner(ip: str, tcp_ports: dict[int, dict]):
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = [ip]
    mock_host = MagicMock()
    mock_host.all_protocols.return_value = ['tcp']
    mock_host.__getitem__ = lambda self, proto: tcp_ports
    mock_nm.__getitem__ = lambda self, host: mock_host
    return mock_nm


def test_scan_host_returns_open_ports_sorted_by_port():
    ip = '192.168.1.1'
    tcp_ports = {
        80: _port_data('http', 'Apache httpd', '2.4.41', 'cpe:/a:apache:http_server:2.4.41'),
        22: _port_data('ssh', 'OpenSSH', '7.9', 'cpe:/a:openbsd:openssh:7.9'),
    }
    with patch('port_scanner.nmap.PortScanner', return_value=_make_mock_scanner(ip, tcp_ports)):
        result = scan_host(ip)

    assert len(result) == 2
    assert result[0].port == 22
    assert result[0].service == 'ssh'
    assert result[0].version == 'OpenSSH 7.9'
    assert result[0].cpes == ['cpe:/a:openbsd:openssh:7.9']
    assert result[1].port == 80
    assert result[1].service == 'http'
    assert result[1].cpes == ['cpe:/a:apache:http_server:2.4.41']


def test_scan_host_with_no_cpe_returns_empty_cpes():
    ip = '192.168.1.2'
    tcp_ports = {8080: _port_data('http-proxy', 'unknown', '', '')}
    with patch('port_scanner.nmap.PortScanner', return_value=_make_mock_scanner(ip, tcp_ports)):
        result = scan_host(ip)

    assert result[0].cpes == []


def test_scan_host_passes_top_ports_flag():
    ip = '192.168.1.1'
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = []
    with patch('port_scanner.nmap.PortScanner', return_value=mock_nm):
        scan_host(ip, top_ports=100)

    mock_nm.scan.assert_called_once_with(hosts=ip, arguments='-sV --open --top-ports 100')


def test_scan_host_passes_port_range_flag():
    ip = '192.168.1.1'
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = []
    with patch('port_scanner.nmap.PortScanner', return_value=mock_nm):
        scan_host(ip, ports='1-1024')

    mock_nm.scan.assert_called_once_with(hosts=ip, arguments='-sV --open -p 1-1024')


def test_scan_host_default_uses_nmap_default_ports():
    ip = '192.168.1.1'
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = []
    with patch('port_scanner.nmap.PortScanner', return_value=mock_nm):
        scan_host(ip)

    mock_nm.scan.assert_called_once_with(hosts=ip, arguments='-sV --open')


def test_scan_host_returns_empty_when_host_unreachable():
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = []
    with patch('port_scanner.nmap.PortScanner', return_value=mock_nm):
        result = scan_host('192.168.1.99')

    assert result == []
