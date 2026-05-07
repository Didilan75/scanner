import ipaddress
import psutil
import socket


def get_local_subnet() -> str:
    """
    Auto-detect the default network interface and return its subnet as a CIDR string.

    Returns:
        str: The subnet in CIDR notation (e.g., '192.168.1.0/24')

    Raises:
        RuntimeError: If the default network interface cannot be detected or if the
                      network configuration cannot be determined.
    """
    # Get the local IP by connecting to an external address (no actual packet sent)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
    except OSError:
        raise RuntimeError(
            "Could not detect default network interface. Check your network connection."
        )

    # Find the interface that has this IP and get its netmask
    for iface_addrs in psutil.net_if_addrs().values():
        for addr in iface_addrs:
            if addr.family == socket.AF_INET and addr.address == local_ip:
                if not addr.netmask:
                    continue
                network = ipaddress.ip_network(
                    f"{local_ip}/{addr.netmask}", strict=False
                )
                return str(network)

    raise RuntimeError(
        "Could not detect default network interface. Check your network connection."
    )
