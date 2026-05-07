from unittest.mock import MagicMock, patch
import pytest
import nmap
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

    assert set(result) == {'192.168.1.1', '192.168.1.10'}
    assert len(result) == 2
    mock_nm.scan.assert_called_once_with(hosts='192.168.1.0/24', arguments='-sn')


def test_discover_hosts_returns_empty_when_no_hosts():
    mock_nm = _make_mock_scanner({})
    with patch('discovery.nmap.PortScanner', return_value=mock_nm):
        result = discover_hosts('10.0.0.0/24')

    assert result == []


def test_discover_hosts_raises_on_nmap_error():
    with patch('discovery.nmap.PortScanner') as mock_cls:
        mock_cls.return_value.scan.side_effect = nmap.PortScannerError('permission denied')
        with pytest.raises(RuntimeError, match='nmap ping sweep failed'):
            discover_hosts('192.168.1.0/24')
