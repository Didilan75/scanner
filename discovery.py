import nmap


def discover_hosts(subnet: str) -> list[str]:
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=subnet, arguments='-sn')
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap ping sweep failed: {e}") from e
    return [host for host in nm.all_hosts() if nm[host].state() == 'up']
