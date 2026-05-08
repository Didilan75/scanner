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
    const pn = mk('span', 'port-num'); pn.append(txt(p.port + '/' + p.protocol + '  '));
    const ps = mk('span', 'port-svc'); ps.append(txt(p.service + (p.version ? '  ' : '')));
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
