import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from network import get_local_subnet
from discovery import discover_hosts
from port_scanner import scan_host
from cve import lookup_cves
from kev import load_kev_catalog
from html_reporter import generate_html, save_and_open
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
    parser.add_argument(
        '--html', action='store_true',
        help='Generate HTML dashboard and open in browser',
    )
    parser.add_argument(
        '--kev-file', dest='kev_file',
        help='Path to local CISA KEV catalog JSON (skips download)',
    )
    args = parser.parse_args()

    if not _check_nmap():
        console.print('[red]Error: nmap not found. Install from https://nmap.org[/red]')
        sys.exit(1)

    try:
        subnet = get_local_subnet()
    except RuntimeError as e:
        console.print(f'[red]Error: {e}[/red]')
        sys.exit(1)

    kev_set = load_kev_catalog(kev_file=args.kev_file)

    with make_progress() as progress:
        task = progress.add_task('Discovering hosts...', total=None)
        try:
            alive = discover_hosts(subnet)
        except RuntimeError as e:
            console.print(f'[red]Error during host discovery: {e}[/red]')
            sys.exit(1)
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
            try:
                ports = scan_host(ip, ports=args.ports, top_ports=args.top_ports)
            except RuntimeError as e:
                console.print(f'[yellow]Warning: port scan failed for {ip}: {e}[/yellow]')
                progress.advance(task)
                continue
            cve_map: dict = {}
            for port in ports:
                for cpe in port.cpes:
                    if cpe not in cve_map:
                        cves = lookup_cves(cpe, api_key=args.nvd_key)
                        for cve in cves:
                            cve.kev = cve.cve_id in kev_set
                        cve_map[cpe] = cves
            print_host(ip, ports, cve_map)
            scan_results.append({'ip': ip, 'ports': ports, 'cve_map': cve_map})
            total_ports += len(ports)
            total_cves += sum(len(v) for v in cve_map.values())
            progress.advance(task)

    print_final_summary(len(alive), total_ports, total_cves)

    if args.output:
        data = serialize_results(subnet, scan_results)
        try:
            with open(args.output, 'w') as f:
                json.dump(data, f, indent=2)
            console.print(f'\n[green]Report saved to {args.output}[/green]')
        except OSError as e:
            console.print(f'[red]Error saving report to {args.output}: {e}[/red]')

    if args.html:
        scan_time = datetime.now(timezone.utc).isoformat()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html = generate_html(subnet, scan_time, scan_results)
        html_path = Path(f'scanner_report_{timestamp}.html')
        save_and_open(html, html_path)


if __name__ == '__main__':
    main()
