# KEV Integration & HTML Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add CISA Known Exploited Vulnerabilities (KEV) cross-referencing with `[KEV]` badges in terminal and JSON output, plus a self-contained dark-themed HTML dashboard that auto-opens in the browser after a scan.

**Architecture:** New `kev.py` loads the KEV catalog from a local file or CISA download with 24h cache, returning `set[str]` of CVE IDs. `CVEResult` gains a `kev: bool` field stamped in `main.py`. `reporter.py` gains a `[KEV]` terminal badge and includes `kev` in JSON serialization. New `html_reporter.py` generates a self-contained HTML file (data injected as JSON in `<script>`, rendered by vanilla JS) and opens it via `webbrowser.open()`. New `--html` and `--kev-file` flags added to CLI.

**Tech Stack:** Python 3.10+, requests (already in requirements.txt), stdlib only for HTML (`pathlib`, `webbrowser`, `json`, `warnings`, `datetime`). No new dependencies.

---

## File Structure

```
scanner/
├── kev.py                   # NEW: load/cache CISA KEV catalog → set[str]
├── html_reporter.py         # NEW: generate + open self-contained HTML dashboard
├── cve.py                   # Add kev: bool = False to CVEResult dataclass
├── reporter.py              # Add [KEV] badge in print_host; add kev to serialize_results
├── main.py                  # Add --html, --kev-file; KEV load + stamp; HTML generation
└── tests/
    ├── test_kev.py          # NEW: 7 tests
    ├── test_html_reporter.py # NEW: 5 tests
    ├── test_cve.py          # +1 test: kev defaults to False
    ├── test_reporter.py     # +2 tests: KEV badge in terminal; kev in serialize_results
    └── test_main.py         # +3 tests; update 5 existing tests to patch load_kev_catalog
```

---

### Task 1: `kev.py` — KEV Catalog Loader

**Files:**
- Create: `kev.py`
- Create: `tests/test_kev.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_kev.py`:

```python
import json
import os
import time
import warnings
from pathlib import Path
from unittest.mock import patch, MagicMock

import requests

from kev import load_kev_catalog, CISA_KEV_URL

SAMPLE_KEV = {
    'vulnerabilities': [
        {'cveID': 'CVE-2021-44228'},
        {'cveID': 'CVE-2021-41773'},
    ]
}


def test_load_from_local_file(tmp_path):
    kev_file = tmp_path / 'kev.json'
    kev_file.write_text(json.dumps(SAMPLE_KEV))
    result = load_kev_catalog(kev_file=str(kev_file))
    assert result == {'CVE-2021-44228', 'CVE-2021-41773'}


def test_local_file_not_found():
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        result = load_kev_catalog(kev_file='/nonexistent/path.json')
    assert result == set()
    assert len(w) == 1


def test_local_file_invalid_json(tmp_path):
    kev_file = tmp_path / 'kev.json'
    kev_file.write_text('not valid json')
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter('always')
        result = load_kev_catalog(kev_file=str(kev_file))
    assert result == set()
    assert len(w) == 1


def test_cache_hit(tmp_path):
    cache_file = tmp_path / 'kev_catalog.json'
    cache_file.write_text(json.dumps(SAMPLE_KEV))
    with patch('kev.requests.get') as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_not_called()
    assert 'CVE-2021-44228' in result


def test_cache_miss_downloads(tmp_path):
    mock_resp = MagicMock()
    mock_resp.json.return_value = SAMPLE_KEV
    with patch('kev.requests.get', return_value=mock_resp) as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_called_once()
    assert 'CVE-2021-44228' in result
    assert (tmp_path / 'kev_catalog.json').exists()


def test_stale_cache_redownloads(tmp_path):
    cache_file = tmp_path / 'kev_catalog.json'
    cache_file.write_text(json.dumps(SAMPLE_KEV))
    old_time = time.time() - 90000  # > 24h ago
    os.utime(cache_file, (old_time, old_time))
    mock_resp = MagicMock()
    mock_resp.json.return_value = SAMPLE_KEV
    with patch('kev.requests.get', return_value=mock_resp) as mock_get:
        result = load_kev_catalog(cache_dir=tmp_path)
    mock_get.assert_called_once()
    assert 'CVE-2021-44228' in result


def test_download_failure_returns_empty(tmp_path):
    with patch('kev.requests.get', side_effect=requests.RequestException('timeout')):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter('always')
            result = load_kev_catalog(cache_dir=tmp_path)
    assert result == set()
    assert len(w) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

```
.\.venv\Scripts\pytest tests/test_kev.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'kev'`

- [ ] **Step 3: Create `kev.py`**

```python
import json
import time
import warnings
from pathlib import Path

import requests

CISA_KEV_URL = (
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
)
_CACHE_MAX_AGE = 86400  # 24 hours in seconds


def _default_cache_path() -> Path:
    cache_dir = Path.home() / '.cache' / 'scanner'
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / 'kev_catalog.json'


def _parse_catalog(data: dict) -> set[str]:
    return {v['cveID'] for v in data.get('vulnerabilities', [])}


def _load_json(path: Path) -> set[str]:
    with open(path, encoding='utf-8') as f:
        return _parse_catalog(json.load(f))


def _download_and_cache(cache_path: Path) -> set[str]:
    resp = requests.get(CISA_KEV_URL, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    cache_path.write_text(json.dumps(data), encoding='utf-8')
    return _parse_catalog(data)


def load_kev_catalog(
    kev_file: str | None = None,
    cache_dir: Path | None = None,
) -> set[str]:
    """Return set of CVE IDs from the CISA KEV catalog.

    If kev_file is given, load from that path (no network call).
    Otherwise download from CISA with a 24h local cache.
    On any failure, warn and return empty set so the scan continues.
    """
    if kev_file is not None:
        try:
            return _load_json(Path(kev_file))
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            warnings.warn(
                f'KEV file load failed ({e}). Exploit status will not be shown.',
                stacklevel=2,
            )
            return set()

    cache_path = (cache_dir / 'kev_catalog.json') if cache_dir else _default_cache_path()

    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < _CACHE_MAX_AGE:
            try:
                return _load_json(cache_path)
            except (json.JSONDecodeError, KeyError):
                cache_path.unlink(missing_ok=True)

    try:
        return _download_and_cache(cache_path)
    except Exception as e:
        warnings.warn(
            f'KEV catalog download failed ({e}). Exploit status will not be shown.',
            stacklevel=2,
        )
        return set()
```

- [ ] **Step 4: Run tests to verify they pass**

```
.\.venv\Scripts\pytest tests/test_kev.py -v
```
Expected: 7 PASSED

- [ ] **Step 5: Commit**

```
git add kev.py tests/test_kev.py
git commit -m "feat: add kev.py — CISA KEV catalog loader with 24h cache"
```

---

### Task 2: `CVEResult.kev` field

**Files:**
- Modify: `cve.py` (CVEResult dataclass)
- Modify: `tests/test_cve.py` (add one test at end)

- [ ] **Step 1: Write the failing test**

Append to end of `tests/test_cve.py`:

```python
def test_cve_result_kev_defaults_false():
    cve = CVEResult(
        cve_id='CVE-2021-44228', cvss_score=10.0,
        severity='CRITICAL', description='Log4Shell',
    )
    assert cve.kev is False
```

- [ ] **Step 2: Run test to verify it fails**

```
.\.venv\Scripts\pytest tests/test_cve.py::test_cve_result_kev_defaults_false -v
```
Expected: FAIL with `TypeError` (unexpected keyword argument or AttributeError)

- [ ] **Step 3: Add `kev` field to `CVEResult` in `cve.py`**

Current `CVEResult` in `cve.py`:

```python
@dataclass
class CVEResult:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
```

Replace with:

```python
@dataclass
class CVEResult:
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    kev: bool = False
```

- [ ] **Step 4: Run all cve tests**

```
.\.venv\Scripts\pytest tests/test_cve.py -v
```
Expected: 8 PASSED

- [ ] **Step 5: Commit**

```
git add cve.py tests/test_cve.py
git commit -m "feat: add kev field to CVEResult dataclass"
```

---

### Task 3: Terminal `[KEV]` badge + `serialize_results` update

**Files:**
- Modify: `reporter.py` (`print_host` and `serialize_results`)
- Modify: `tests/test_reporter.py` (add 2 tests)

- [ ] **Step 1: Write the failing tests**

Append to end of `tests/test_reporter.py`:

```python
def test_print_host_shows_kev_badge():
    from io import StringIO
    from unittest.mock import patch
    from rich.console import Console
    import reporter

    port = PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache 2.4.41', cpes=['cpe:/a:apache'],
    )
    cve = CVEResult(
        cve_id='CVE-2021-41773', cvss_score=9.8,
        severity='CRITICAL', description='Path traversal', kev=True,
    )
    buf = StringIO()
    test_console = Console(file=buf, highlight=False, markup=True)
    with patch.object(reporter, 'console', test_console):
        reporter.print_host('192.168.1.1', [port], {'cpe:/a:apache': [cve]})
    assert '[KEV]' in buf.getvalue()


def test_serialize_results_includes_kev_field():
    port = PortResult(
        port=22, protocol='tcp', state='open', service='ssh',
        version='OpenSSH 7.9', cpes=['cpe:/a:openbsd:openssh:7.9'],
    )
    cve = CVEResult(
        cve_id='CVE-2023-38408', cvss_score=9.8,
        severity='CRITICAL', description='RCE', kev=True,
    )
    scan_results = [{'ip': '192.168.1.1', 'ports': [port], 'cve_map': {'cpe:/a:openbsd:openssh:7.9': [cve]}}]
    output = serialize_results('192.168.1.0/24', scan_results)
    assert output['hosts'][0]['ports'][0]['cves'][0]['kev'] is True
```

- [ ] **Step 2: Run tests to verify they fail**

```
.\.venv\Scripts\pytest tests/test_reporter.py::test_print_host_shows_kev_badge tests/test_reporter.py::test_serialize_results_includes_kev_field -v
```
Expected: FAIL — `[KEV]` not in output; `kev` key missing

- [ ] **Step 3: Update `print_host` in `reporter.py`**

Current CVE printing block in `print_host` (the `for cve in host_cves:` block):

```python
        for cve in host_cves:
            color = _cvss_color(cve.cvss_score)
            label = _severity_label(cve.cvss_score)
            desc = escape(cve.description[:80])
            console.print(
                f"             [{color}]{escape(cve.cve_id)}  {cve.cvss_score}  "
                f"\\[{label}\\][/{color}]  {desc}"
            )
```

Replace with:

```python
        for cve in host_cves:
            color = _cvss_color(cve.cvss_score)
            label = _severity_label(cve.cvss_score)
            desc = escape(cve.description[:80])
            kev_badge = '  [bold red]\\[KEV\\][/bold red]' if cve.kev else ''
            console.print(
                f"             [{color}]{escape(cve.cve_id)}  {cve.cvss_score}  "
                f"\\[{label}\\][/{color}]{kev_badge}  {desc}"
            )
```

- [ ] **Step 4: Update `serialize_results` in `reporter.py`**

Current CVE dict in `serialize_results`:

```python
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
```

Replace with:

```python
                    'cves': [
                        {
                            'cve_id': c.cve_id,
                            'cvss_score': c.cvss_score,
                            'severity': c.severity,
                            'description': c.description,
                            'kev': c.kev,
                        }
                        for cpe in p.cpes
                        for c in entry['cve_map'].get(cpe, [])
                    ],
```

- [ ] **Step 5: Run all reporter tests**

```
.\.venv\Scripts\pytest tests/test_reporter.py -v
```
Expected: 5 PASSED

- [ ] **Step 6: Commit**

```
git add reporter.py tests/test_reporter.py
git commit -m "feat: add KEV badge to terminal output and kev field to JSON serialization"
```

---

### Task 4: `html_reporter.py` — HTML Dashboard Generator

**Files:**
- Create: `html_reporter.py`
- Create: `tests/test_html_reporter.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_html_reporter.py`:

```python
from pathlib import Path
from unittest.mock import patch

from port_scanner import PortResult
from cve import CVEResult
from html_reporter import generate_html, save_and_open


def _scan_results(kev: bool = False) -> list[dict]:
    port = PortResult(
        port=80, protocol='tcp', state='open', service='http',
        version='Apache 2.4.41', cpes=['cpe:/a:apache:http_server:2.4.41'],
    )
    cve = CVEResult(
        cve_id='CVE-2021-41773', cvss_score=9.8,
        severity='CRITICAL', description='Path traversal', kev=kev,
    )
    return [{'ip': '192.168.1.1', 'ports': [port], 'cve_map': {'cpe:/a:apache:http_server:2.4.41': [cve]}}]


def test_generate_html_contains_host_ip():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results())
    assert '192.168.1.1' in html


def test_generate_html_contains_cve_id():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results())
    assert 'CVE-2021-41773' in html


def test_generate_html_kev_flag_true_in_data():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results(kev=True))
    assert '"kev": true' in html


def test_generate_html_kev_flag_false_in_data():
    html = generate_html('192.168.1.0/24', '2026-05-08T14:32:00Z', _scan_results(kev=False))
    assert '"kev": false' in html


def test_save_and_open_writes_file(tmp_path):
    out = tmp_path / 'report.html'
    with patch('html_reporter.webbrowser.open', return_value=True):
        save_and_open('<html>test</html>', out)
    assert out.exists()
    assert '<html>test</html>' in out.read_text(encoding='utf-8')
```

- [ ] **Step 2: Run tests to verify they fail**

```
.\.venv\Scripts\pytest tests/test_html_reporter.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'html_reporter'`

- [ ] **Step 3: Create `html_reporter.py`**

```python
import json
import webbrowser
from pathlib import Path

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Subnet Scanner Report</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: #0f172a; color: #e2e8f0; font-family: "Courier New", monospace; padding: 2rem; }
h1 { color: #38bdf8; font-size: 1.5rem; margin-bottom: 0.25rem; }
.meta { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }
.stats { display: flex; gap: 1.5rem; margin-bottom: 2rem; flex-wrap: wrap; }
.stat { background: #1e293b; border-radius: 0.5rem; padding: 0.75rem 1.5rem; }
.stat-value { font-size: 1.5rem; font-weight: bold; color: #38bdf8; }
.stat-label { font-size: 0.7rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; }
.host-card { background: #1e293b; border-radius: 0.5rem; margin-bottom: 1rem; overflow: hidden; }
.host-header { background: #334155; padding: 0.6rem 1rem; color: #60a5fa; font-weight: bold; }
.port-row { padding: 0.5rem 1rem; border-top: 1px solid #0f172a; }
.port-meta { font-size: 0.875rem; margin-bottom: 0.25rem; }
.port-num { color: #22d3ee; }
.port-svc { color: #e2e8f0; }
.port-ver { color: #64748b; }
.cve-list { padding-left: 1.5rem; margin-top: 0.25rem; }
.cve-row { font-size: 0.8rem; padding: 0.15rem 0; display: flex; align-items: center; gap: 0.4rem; flex-wrap: wrap; }
.sev-badge { border-radius: 0.2rem; padding: 0.05rem 0.35rem; font-size: 0.7rem; font-weight: bold; color: #0f172a; }
.kev-badge { background: #ef4444; color: #fff; border-radius: 0.2rem; padding: 0.05rem 0.4rem; font-size: 0.7rem; font-weight: bold; }
.cve-desc { color: #94a3b8; }
.no-data { color: #475569; font-style: italic; font-size: 0.8rem; padding: 0.2rem 0; }
</style>
</head>
<body>
<h1>Subnet Scanner Report</h1>
<div class="meta" id="meta"></div>
<div class="stats" id="stats"></div>
<div id="hosts"></div>
<script>
const DATA = __DATA__;

function sevColor(s) {
  return s >= 9 ? '#ef4444' : s >= 7 ? '#f97316' : s >= 4 ? '#eab308' : '#94a3b8';
}
function sevLabel(s) {
  return s >= 9 ? 'CRITICAL' : s >= 7 ? 'HIGH' : s >= 4 ? 'MEDIUM' : 'LOW';
}
function mk(tag, cls) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  return e;
}
function txt(content) { return document.createTextNode(content); }

document.getElementById('meta').textContent = DATA.subnet + ' · ' + DATA.scan_time;

let tp = 0, tc = 0, tk = 0;
DATA.hosts.forEach(h => h.ports.forEach(p => {
  tp++;
  p.cves.forEach(c => { tc++; if (c.kev) tk++; });
}));

const statsEl = document.getElementById('stats');
[[DATA.hosts.length, 'Hosts'], [tp, 'Ports'], [tc, 'CVEs'], [tk, 'KEV']].forEach(([v, l]) => {
  const s = mk('div', 'stat');
  const sv = mk('div', 'stat-value'); sv.append(txt(String(v))); s.appendChild(sv);
  const sl = mk('div', 'stat-label'); sl.append(txt(l)); s.appendChild(sl);
  statsEl.appendChild(s);
});

const hostsEl = document.getElementById('hosts');
DATA.hosts.forEach(h => {
  const card = mk('div', 'host-card');
  const hdr = mk('div', 'host-header'); hdr.append(txt(h.ip)); card.appendChild(hdr);

  if (!h.ports.length) {
    const nr = mk('div', 'port-row'); nr.append(txt('no open ports found')); card.appendChild(nr);
  }

  h.ports.forEach(p => {
    const row = mk('div', 'port-row');
    const meta = mk('div', 'port-meta');
    const pn = mk('span', 'port-num'); pn.append(txt(p.port + '/' + p.protocol + '  '));
    const ps = mk('span', 'port-svc'); ps.append(txt(p.service + (p.version ? '  ' : '')));
    const pv = mk('span', 'port-ver'); pv.append(txt(p.version || ''));
    meta.appendChild(pn); meta.appendChild(ps); meta.appendChild(pv);
    row.appendChild(meta);

    if (p.cves.length) {
      const cl = mk('div', 'cve-list');
      p.cves.forEach(c => {
        const col = sevColor(c.cvss_score);
        const cr = mk('div', 'cve-row');

        const cid = mk('span', null); cid.style.color = col; cid.style.fontWeight = 'bold';
        cid.append(txt(c.cve_id)); cr.appendChild(cid);

        const sc = mk('span', null); sc.style.color = col;
        sc.append(txt(String(c.cvss_score))); cr.appendChild(sc);

        const sb = mk('span', 'sev-badge');
        sb.style.background = col; sb.append(txt(sevLabel(c.cvss_score))); cr.appendChild(sb);

        if (c.kev) {
          const kb = mk('span', 'kev-badge'); kb.append(txt('KEV')); cr.appendChild(kb);
        }

        const desc = mk('span', 'cve-desc'); desc.append(txt(c.description)); cr.appendChild(desc);
        cl.appendChild(cr);
      });
      row.appendChild(cl);
    } else {
      const nd = mk('div', 'cve-list no-data'); nd.append(txt('no CVEs found')); row.appendChild(nd);
    }
    card.appendChild(row);
  });
  hostsEl.appendChild(card);
});
</script>
</body>
</html>"""


def _build_data(subnet: str, scan_time: str, scan_results: list[dict]) -> dict:
    hosts = []
    for entry in scan_results:
        ports = []
        for p in entry['ports']:
            cves = []
            for cpe in p.cpes:
                for c in entry['cve_map'].get(cpe, []):
                    cves.append({
                        'cve_id': c.cve_id,
                        'cvss_score': c.cvss_score,
                        'severity': c.severity,
                        'description': c.description[:80],
                        'kev': c.kev,
                    })
            ports.append({
                'port': p.port,
                'protocol': p.protocol,
                'service': p.service,
                'version': p.version,
                'cves': cves,
            })
        hosts.append({'ip': entry['ip'], 'ports': ports})
    return {'subnet': subnet, 'scan_time': scan_time, 'hosts': hosts}


def generate_html(subnet: str, scan_time: str, scan_results: list[dict]) -> str:
    data = _build_data(subnet, scan_time, scan_results)
    data_json = json.dumps(data, indent=2)
    return _HTML_TEMPLATE.replace('__DATA__', data_json)


def save_and_open(html: str, path: Path) -> None:
    try:
        path.write_text(html, encoding='utf-8')
    except OSError as e:
        print(f'Error saving dashboard to {path}: {e}')
        return
    uri = path.resolve().as_uri()
    if not webbrowser.open(uri):
        print(f'Dashboard saved to {path} — open it manually in your browser')
```

- [ ] **Step 4: Run tests to verify they pass**

```
.\.venv\Scripts\pytest tests/test_html_reporter.py -v
```
Expected: 5 PASSED

- [ ] **Step 5: Commit**

```
git add html_reporter.py tests/test_html_reporter.py
git commit -m "feat: add html_reporter.py — self-contained dark-themed HTML dashboard"
```

---

### Task 5: Wire into `main.py` — `--html`, `--kev-file`, KEV stamping

**Files:**
- Modify: `main.py` (full rewrite)
- Modify: `tests/test_main.py` (3 new tests + patch 5 existing tests)

- [ ] **Step 1: Write the failing tests**

First, add `patch('main.load_kev_catalog', return_value=set())` to every existing test that reaches past the nmap check. Open `tests/test_main.py` and add that patch line to these five tests:

- `test_main_runs_full_pipeline_without_output`
- `test_main_saves_json_output`
- `test_main_exits_when_no_hosts_found`
- `test_main_exits_when_host_discovery_fails`
- `test_main_skips_host_when_port_scan_fails`

Example — `test_main_runs_full_pipeline_without_output` becomes:

```python
def test_main_runs_full_pipeline_without_output():
    import main as m
    mock_progress, mock_ctx = _make_progress_mock()

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()
```

Apply the same `patch('main.load_kev_catalog', return_value=set()), \` addition to the other four tests listed above.

Then append these three new tests to end of `tests/test_main.py`:

```python
def test_main_html_flag_generates_and_opens_dashboard():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--html']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()), \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress), \
         patch('main.generate_html', return_value='<html></html>') as mock_gen, \
         patch('main.save_and_open') as mock_open:
        m.main()

    mock_gen.assert_called_once()
    mock_open.assert_called_once()


def test_main_kev_file_flag_passed_to_load_kev_catalog():
    import main as m
    mock_progress, _ = _make_progress_mock()

    with patch('sys.argv', ['main.py', '--kev-file', 'my_kev.json']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=MOCK_CVES), \
         patch('main.load_kev_catalog', return_value=set()) as mock_kev, \
         patch('main.print_summary'), \
         patch('main.print_host'), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    mock_kev.assert_called_once_with(kev_file='my_kev.json')


def test_main_stamps_kev_on_matching_cves():
    import main as m
    mock_progress, _ = _make_progress_mock()
    stamped_flags = []

    def capture_print_host(ip, ports, cve_map):
        for cves in cve_map.values():
            stamped_flags.extend(c.kev for c in cves)

    kev_cve = CVEResult(
        cve_id='CVE-2023-38408', cvss_score=9.8,
        severity='CRITICAL', description='RCE',
    )

    with patch('sys.argv', ['main.py']), \
         patch('main._check_nmap', return_value=True), \
         patch('main.get_local_subnet', return_value='192.168.1.0/24'), \
         patch('main.discover_hosts', return_value=['192.168.1.1']), \
         patch('main.scan_host', return_value=MOCK_PORTS), \
         patch('main.lookup_cves', return_value=[kev_cve]), \
         patch('main.load_kev_catalog', return_value={'CVE-2023-38408'}), \
         patch('main.print_summary'), \
         patch('main.print_host', side_effect=capture_print_host), \
         patch('main.print_final_summary'), \
         patch('main.make_progress', mock_progress):
        m.main()

    assert any(stamped_flags), 'Expected CVE-2023-38408 to be stamped kev=True'
```

- [ ] **Step 2: Run tests to verify they fail**

```
.\.venv\Scripts\pytest tests/test_main.py -v
```
Expected: new tests FAIL (`ImportError: cannot import name 'load_kev_catalog' from 'main'`); existing tests may also fail

- [ ] **Step 3: Replace `main.py` with the updated version**

```python
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
```

- [ ] **Step 4: Run full test suite**

```
.\.venv\Scripts\pytest -v
```
Expected: 38 PASSED (29 existing + 9 new)

- [ ] **Step 5: Commit and push**

```
git add main.py tests/test_main.py
git commit -m "feat: wire KEV stamping, --kev-file, and --html dashboard into main.py"
git push
```
