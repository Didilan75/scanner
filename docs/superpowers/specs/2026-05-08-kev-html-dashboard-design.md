# KEV Integration & HTML Dashboard — Design Spec

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add CISA Known Exploited Vulnerabilities (KEV) catalog cross-referencing and a self-contained HTML dashboard that auto-opens in the browser after a scan.

**Architecture:** New `kev.py` module loads the KEV catalog (local file or auto-downloaded with 24h cache). `CVEResult` gets a `kev: bool` field. After NVD lookup, `main.py` stamps each result. Terminal output gains a `[KEV]` badge. A new `html_reporter.py` generates a self-contained HTML file (data injected as JSON into a `<script>` tag, rendered by vanilla JS) and opens it via `webbrowser.open()`.

**Tech Stack:** Python stdlib only — `pathlib`, `webbrowser`, `json`, `datetime`. No new dependencies.

---

## File Structure

```
scanner/
├── main.py              # +--html, +--kev-file args; KEV stamping logic
├── kev.py               # NEW: load/cache CISA KEV catalog → set[str]
├── html_reporter.py     # NEW: generate + open self-contained HTML dashboard
├── cve.py               # CVEResult gains kev: bool = False field
├── reporter.py          # print_host gains [KEV] badge in terminal output
└── tests/
    ├── test_kev.py      # NEW
    └── test_html_reporter.py  # NEW
```

---

## Module Contracts

### `kev.py`

```python
def load_kev_catalog(
    kev_file: str | None = None,
    cache_dir: Path | None = None,
) -> set[str]:
    """
    Return set of CVE IDs in the CISA KEV catalog.

    If kev_file is given: load directly from that path, no download.
    Otherwise: download from CISA, cache at cache_dir (default ~/.cache/scanner/).
    Cache is valid for 24 hours. On any failure: log warning, return empty set.
    """
```

- **CISA KEV URL:** `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
- **Cache path:** `~/.cache/scanner/kev_catalog.json`
- **Staleness check:** compare `Path.stat().st_mtime` to `time.time() - 86400`
- **Failure modes:** file not found, JSON parse error, network error → `warnings.warn(...)`, return `set()`
- **CVE ID extraction:** `{v['cveID'] for v in data['vulnerabilities']}`

### `cve.py` (modified)

```python
@dataclass
class CVEResult:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    kev: bool = False        # True if CVE-ID appears in CISA KEV catalog
```

`lookup_cves()` is unchanged — `kev` stamping happens in `main.py`.

### `html_reporter.py`

```python
def generate_html(
    subnet: str,
    scan_time: str,
    scan_results: list[dict],
) -> str:
    """Return a complete self-contained HTML string."""

def save_and_open(html: str, path: Path) -> None:
    """Write html to path and open in default browser via webbrowser.open()."""
```

**HTML structure:**
- Dark theme, single file, no external dependencies
- Header: title, subnet, scan timestamp
- Summary bar: host count · port count · CVE count · KEV count
- One card per host: IP header, then one row per port showing port/proto, service, version
- Each CVE row: ID · score · severity badge · description (80 chars) · `[KEV]` badge if `kev=True`
- CVSS color mapping matches terminal: ≥9.0 red, ≥7.0 orange, ≥4.0 yellow, <4.0 white/grey
- KEV badge: bold red pill-shaped label
- Data injected as a JSON blob: `<script>const DATA = {...};</script>`; ~50 lines of vanilla JS renders it

**Auto-named output:** `scanner_report_YYYYMMDD_HHMMSS.html` in current working directory.

### `reporter.py` (modified)

`print_host()` appends `[bold red]\[KEV\][/bold red]` after the severity bracket when `cve.kev is True`:

```
CVE-2021-44228  10.0  [CRITICAL]  [KEV]  Log4Shell remote code execution...
```

### `main.py` (modified)

**New CLI arguments:**
```python
parser.add_argument('--html', action='store_true', help='Generate HTML dashboard and open in browser')
parser.add_argument('--kev-file', dest='kev_file', help='Path to local KEV catalog JSON')
```

**Orchestration additions:**
```python
# 1. Load KEV catalog before scan loop
kev_set = load_kev_catalog(kev_file=args.kev_file)

# 2. After lookup_cves() for each CPE, stamp kev field
for cve in cves:
    cve.kev = cve.cve_id in kev_set

# 3. After scan loop, if --html
if args.html:
    html = generate_html(subnet, scan_time, scan_results)
    save_and_open(html, Path(f"scanner_report_{timestamp}.html"))
```

---

## CLI Usage

```bash
# Terminal only (no change)
python main.py

# With local KEV file
python main.py --kev-file kev_catalog.json

# HTML dashboard (auto-opens in browser)
python main.py --html

# HTML + local KEV file
python main.py --html --kev-file kev_catalog.json

# HTML + JSON output
python main.py --html --output report.json

# Full combo
python main.py --html --kev-file kev_catalog.json --output report.json --nvd-key YOUR_KEY
```

---

## Terminal Output Change

```
192.168.1.1
  22/tcp   ssh    OpenSSH 7.9
           CVE-2023-38408  9.8  [CRITICAL]  [KEV]  ssh-agent remote code execution...
  80/tcp   http   Apache httpd 2.4.41
           CVE-2021-41773  9.8  [CRITICAL]  [KEV]  Path traversal and RCE in Apache...
```

---

## HTML Dashboard Layout

```
┌──────────────────────────────────────────────────────┐
│  Subnet Scanner Report                 [dark theme]  │
│  192.168.1.0/24  ·  2026-05-08 14:32                │
│                                                      │
│  8 hosts  ·  23 ports  ·  14 CVEs  ·  3 KEV         │
├──────────────────────────────────────────────────────┤
│  ┌── 192.168.1.1 ─────────────────────────────────┐  │
│  │  22/tcp   ssh    OpenSSH 7.9                   │  │
│  │    CVE-2023-38408  9.8  [CRITICAL] [KEV]  ...  │  │
│  │  80/tcp   http   Apache httpd 2.4.41           │  │
│  │    CVE-2021-41773  9.8  [CRITICAL] [KEV]  ...  │  │
│  └────────────────────────────────────────────────┘  │
│  ┌── 192.168.1.15 ────────────────────────────────┐  │
│  │  3306/tcp  mysql  MySQL 8.0.26                 │  │
│  │    CVE-2021-35604  6.5  [MEDIUM]  ...          │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

---

## JSON Output Schema (updated)

```json
{
  "cve_id": "CVE-2021-44228",
  "cvss_score": 10.0,
  "severity": "CRITICAL",
  "description": "Log4Shell...",
  "kev": true
}
```

---

## Error Handling

| Scenario | Behavior |
|---|---|
| `--kev-file` path not found | `warnings.warn`, return empty set, scan continues |
| `--kev-file` invalid JSON | `warnings.warn`, return empty set, scan continues |
| CISA download fails | `warnings.warn`, return empty set, scan continues |
| Cache file corrupted | Delete cache, re-download; on failure return empty set |
| `--html` write fails (disk full, permissions) | Print error, do not crash |
| `webbrowser.open()` fails | Print file path so user can open manually |

---

## Tests

### `test_kev.py`
- `test_load_from_local_file` — reads valid local JSON, returns correct set of CVE IDs
- `test_local_file_not_found` — missing path → empty set + warning
- `test_local_file_invalid_json` — bad JSON → empty set + warning
- `test_cache_hit` — valid cache file < 24h old → no download, returns cached set
- `test_cache_miss_downloads` — no cache file → downloads, writes cache, returns set
- `test_stale_cache_redownloads` — cache > 24h old → re-downloads
- `test_download_failure_returns_empty` — network error → empty set + warning

### `test_html_reporter.py`
- `test_generate_html_contains_host_ip` — IP address appears in output
- `test_generate_html_contains_cve_id` — CVE ID appears in output
- `test_generate_html_kev_badge_present` — `[KEV]` badge appears for kev=True CVEs
- `test_generate_html_no_kev_badge_when_false` — no KEV badge for kev=False CVEs
- `test_save_and_open_writes_file` — file is written to specified path

### Existing test updates
- `test_cve.py` — `CVEResult` defaults `kev=False`
- `test_reporter.py` — `[KEV]` badge appears in terminal output when `cve.kev=True`
- `test_main.py` — `--html` flag triggers `generate_html` + `save_and_open`; `--kev-file` passes path to `load_kev_catalog`
