from dataclasses import dataclass, field
import nmap


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str
    service: str
    version: str
    cpes: list[str] = field(default_factory=list)


def scan_host(
    ip: str,
    ports: str | None = None,
    top_ports: int | None = None,
) -> list[PortResult]:
    nm = nmap.PortScanner()
    args = '-sV --open'
    if ports:
        args += f' -p {ports}'
    elif top_ports:
        args += f' --top-ports {top_ports}'
    try:
        nm.scan(hosts=ip, arguments=args)
    except nmap.PortScannerError as e:
        raise RuntimeError(f"nmap port scan failed for {ip}: {e}") from e

    if ip not in nm.all_hosts():
        return []

    results = []
    for proto in nm[ip].all_protocols():
        for port, data in nm[ip][proto].items():
            cpe_raw = data.get('cpe', '')
            cpes = [cpe_raw] if cpe_raw else []
            product = data.get('product', '')
            version = data.get('version', '')
            version_str = " ".join(filter(None, [product, version]))
            results.append(PortResult(
                port=port,
                protocol=proto,
                state=data.get('state', ''),
                service=data.get('name', ''),
                version=version_str,
                cpes=cpes,
            ))

    return sorted(results, key=lambda r: r.port)
