from port_scanner import PortResult
from cve import CVEResult
from reporter import _cvss_color, _severity_label, serialize_results


def test_cvss_color_boundaries():
    assert _cvss_color(9.0) == 'red bold'
    assert _cvss_color(9.8) == 'red bold'
    assert _cvss_color(7.0) == 'orange1'
    assert _cvss_color(8.9) == 'orange1'
    assert _cvss_color(4.0) == 'yellow'
    assert _cvss_color(6.9) == 'yellow'
    assert _cvss_color(0.0) == 'white'
    assert _cvss_color(3.9) == 'white'


def test_severity_label_boundaries():
    assert _severity_label(9.8) == 'CRITICAL'
    assert _severity_label(9.0) == 'CRITICAL'
    assert _severity_label(8.9) == 'HIGH'
    assert _severity_label(7.0) == 'HIGH'
    assert _severity_label(6.9) == 'MEDIUM'
    assert _severity_label(4.0) == 'MEDIUM'
    assert _severity_label(3.9) == 'LOW'
    assert _severity_label(0.0) == 'LOW'


def test_serialize_results_full_structure():
    ports = [
        PortResult(
            port=22, protocol='tcp', state='open', service='ssh',
            version='OpenSSH 7.9', cpes=['cpe:/a:openbsd:openssh:7.9'],
        ),
        PortResult(
            port=8080, protocol='tcp', state='open', service='http-proxy',
            version='', cpes=[],
        ),
    ]
    cve_map = {
        'cpe:/a:openbsd:openssh:7.9': [
            CVEResult(
                cve_id='CVE-2023-38408', cvss_score=9.8,
                severity='CRITICAL', description='RCE via ssh-agent',
            ),
        ]
    }
    scan_results = [{'ip': '192.168.1.1', 'ports': ports, 'cve_map': cve_map}]

    output = serialize_results('192.168.1.0/24', scan_results)

    assert output['subnet'] == '192.168.1.0/24'
    assert 'scan_time' in output
    assert len(output['hosts']) == 1

    host = output['hosts'][0]
    assert host['ip'] == '192.168.1.1'
    assert len(host['ports']) == 2

    port_22 = host['ports'][0]
    assert port_22['port'] == 22
    assert port_22['service'] == 'ssh'
    assert port_22['cpes'] == ['cpe:/a:openbsd:openssh:7.9']
    assert len(port_22['cves']) == 1
    assert port_22['cves'][0]['cve_id'] == 'CVE-2023-38408'
    assert port_22['cves'][0]['cvss_score'] == 9.8

    port_8080 = host['ports'][1]
    assert port_8080['cves'] == []
