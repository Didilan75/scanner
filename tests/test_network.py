import ipaddress
import socket
from unittest.mock import patch, MagicMock
from network import get_local_subnet


def _make_mock_addrs(ip: str, netmask: str):
    """Return psutil-style net_if_addrs() result with one matching interface."""
    addr = MagicMock()
    addr.family = socket.AF_INET
    addr.address = ip
    addr.netmask = netmask
    return {'eth0': [addr]}


def test_get_local_subnet_returns_cidr():
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.getsockname.return_value = ('192.168.1.100', 0)

    with patch('network.socket.socket', return_value=mock_sock), \
         patch('network.psutil.net_if_addrs', return_value=_make_mock_addrs('192.168.1.100', '255.255.255.0')):
        result = get_local_subnet()

    assert result == '192.168.1.0/24'
    import ipaddress as ip_mod
    assert str(ip_mod.ip_network(result, strict=True)) == '192.168.1.0/24'


def test_get_local_subnet_raises_on_socket_error():
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.connect.side_effect = OSError('Network unreachable')

    with patch('network.socket.socket', return_value=mock_sock):
        try:
            get_local_subnet()
            assert False, 'Expected RuntimeError'
        except RuntimeError as e:
            assert 'detect' in str(e).lower()


def test_get_local_subnet_raises_when_ip_not_in_interfaces():
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.getsockname.return_value = ('10.0.0.1', 0)

    # Interface list does NOT contain 10.0.0.1
    with patch('network.socket.socket', return_value=mock_sock), \
         patch('network.psutil.net_if_addrs', return_value=_make_mock_addrs('192.168.1.100', '255.255.255.0')):
        try:
            get_local_subnet()
            assert False, 'Expected RuntimeError'
        except RuntimeError as e:
            assert 'detect' in str(e).lower()
