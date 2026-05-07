from unittest.mock import MagicMock, patch
from discovery import discover_hosts


def _make_mock_scanner(hosts_states: dict[str, str]):
    mock_nm = MagicMock()
    mock_nm.all_hosts.return_value = list(hosts_states.keys())
    host_mocks = {
        ip: MagicMock(**{'state.return_value': state})
        for ip, state in hosts_states.items()
    }
    mock_nm.__getitem__ = lambda self, host: host_mocks[host]
    return mock_nm


def test_discover_hosts_returns_only_alive():
    mock_nm = _make_mock_scanner({
        '192.168.1.1': 'up',
        '192.168.1.5': 'down',
        '192.168.1.10': 'up',
    })
    with patch('discovery.nmap.PortScanner', return_value=mock_nm):
        result = discover_hosts('192.168.1.0/24')

    assert result == ['192.168.1.1', '192.168.1.10']
    mock_nm.scan.assert_called_once_with(hosts='192.168.1.0/24', arguments='-sn')


def test_discover_hosts_returns_empty_when_no_hosts():
    mock_nm = _make_mock_scanner({})
    with patch('discovery.nmap.PortScanner', return_value=mock_nm):
        result = discover_hosts('10.0.0.0/24')

    assert result == []
