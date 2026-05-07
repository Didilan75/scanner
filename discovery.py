import nmap


def discover_hosts(subnet: str) -> list[str]:
    nm = nmap.PortScanner()
    nm.scan(hosts=subnet, arguments='-sn')
    return [host for host in nm.all_hosts() if nm[host].state() == 'up']
