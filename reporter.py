from datetime import datetime, timezone
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

console = Console()


def _cvss_color(score: float) -> str:
    if score >= 9.0:
        return 'red bold'
    if score >= 7.0:
        return 'orange1'
    if score >= 4.0:
        return 'yellow'
    return 'white'


def _severity_label(score: float) -> str:
    if score >= 9.0:
        return 'CRITICAL'
    if score >= 7.0:
        return 'HIGH'
    if score >= 4.0:
        return 'MEDIUM'
    return 'LOW'


def print_summary(subnet: str, alive_ips: list[str]) -> None:
    console.print(f"\n[bold cyan]Subnet Scanner Agent[/bold cyan]")
    console.print(f"Detected subnet: [bold]{subnet}[/bold]")
    console.print(f"[green]{len(alive_ips)} hosts alive[/green]\n")


def print_host(ip: str, ports: list, cve_map: dict) -> None:
    console.print(f"\n[bold blue]{ip}[/bold blue]")
    if not ports:
        console.print("  [dim]no open ports found[/dim]")
        return
    for port in ports:
        version_part = f"  [dim]{port.version}[/dim]" if port.version else ''
        console.print(
            f"  [cyan]{port.port}/{port.protocol}[/cyan]  "
            f"[white]{port.service}[/white]{version_part}"
        )
        host_cves = [c for cpe in port.cpes for c in cve_map.get(cpe, [])]
        if not port.cpes:
            console.print(f"             [dim]no CPE — CVE lookup skipped[/dim]")
        elif not host_cves:
            console.print(f"             [dim]no CVEs found[/dim]")
        for cve in host_cves:
            color = _cvss_color(cve.cvss_score)
            label = _severity_label(cve.cvss_score)
            desc = cve.description[:80]
            console.print(
                f"             [{color}]{cve.cve_id}  {cve.cvss_score}  "
                f"[{label}][/{color}]  {desc}"
            )


def print_final_summary(total_hosts: int, total_ports: int, total_cves: int) -> None:
    console.print(
        f"\n[bold]Scan complete.[/bold] "
        f"{total_hosts} hosts, {total_ports} open ports, {total_cves} CVEs found."
    )


def make_progress(description: str) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )


def serialize_results(subnet: str, scan_results: list) -> dict:
    return {
        'subnet': subnet,
        'scan_time': datetime.now(timezone.utc).isoformat(),
        'hosts': [
            {
                'ip': entry['ip'],
                'ports': [
                    {
                        'port': p.port,
                        'protocol': p.protocol,
                        'service': p.service,
                        'version': p.version,
                        'cpes': p.cpes,
                        'cves': [
                            {
                                'cve_id': c.cve_id,
                                'cvss_score': c.cvss_score,
                                'severity': c.severity,
                                'description': c.description,
                            }
                            for cpe in p.cpes
                            for c in entry['cve_map'].get(cpe, [])
                        ],
                    }
                    for p in entry['ports']
                ],
            }
            for entry in scan_results
        ],
    }
