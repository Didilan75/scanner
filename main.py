import argparse
import json
import os
import sys

from network import get_local_subnet
from discovery import discover_hosts
from port_scanner import scan_host
from cve import lookup_cves
from reporter import (
    console,
    make_progress,
    print_summary,
    print_host,
    print_final_summary,
    serialize_results,
)


def _check_nmap() -> bool:
    try:
        import nmap
        nmap.PortScanner()
        return True
    except Exception:
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description='Subnet Scanner Agent')
    port_group = parser.add_mutually_exclusive_group()
    port_group.add_argument('--ports', help='Port range, e.g. 1-65535')
    port_group.add_argument(
        '--top-ports', type=int, dest='top_ports', help='Scan top N ports',
    )
    parser.add_argument(
        '--nvd-key', dest='nvd_key',
        default=os.getenv('NVD_API_KEY'),
        help='NVD API key (or set NVD_API_KEY env var)',
    )
    parser.add_argument('--output', help='Save results as JSON to this path')
    args = parser.parse_args()

    if not _check_nmap():
        console.print('[red]Error: nmap not found. Install from https://nmap.org[/red]')
        sys.exit(1)

    try:
        subnet = get_local_subnet()
    except RuntimeError as e:
        console.print(f'[red]Error: {e}[/red]')
        sys.exit(1)

    console.print(f'\n[bold cyan]Subnet Scanner Agent[/bold cyan]')
    console.print(f'Detected subnet: [bold]{subnet}[/bold]\n')

    with make_progress() as progress:
        task = progress.add_task('Discovering hosts...', total=None)
        alive = discover_hosts(subnet)
        progress.update(task, completed=1, total=1)

    print_summary(subnet, alive)

    if not alive:
        console.print('[yellow]No hosts found. Exiting.[/yellow]')
        return

    scan_results = []
    total_ports = 0
    total_cves = 0

    with make_progress() as progress:
        task = progress.add_task('Scanning ports and looking up CVEs...', total=len(alive))
        for ip in alive:
            ports = scan_host(ip, ports=args.ports, top_ports=args.top_ports)
            cve_map: dict = {}
            for port in ports:
                for cpe in port.cpes:
                    if cpe not in cve_map:
                        cve_map[cpe] = lookup_cves(cpe, api_key=args.nvd_key)
            print_host(ip, ports, cve_map)
            scan_results.append({'ip': ip, 'ports': ports, 'cve_map': cve_map})
            total_ports += len(ports)
            total_cves += sum(len(v) for v in cve_map.values())
            progress.advance(task)

    print_final_summary(len(alive), total_ports, total_cves)

    if args.output:
        data = serialize_results(subnet, scan_results)
        with open(args.output, 'w') as f:
            json.dump(data, f, indent=2)
        console.print(f'\n[green]Report saved to {args.output}[/green]')


if __name__ == '__main__':
    main()
