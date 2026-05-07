from unittest.mock import patch, MagicMock
import requests as req
from cve import lookup_cves, CVEResult

NVD_TWO_CVES = {
    'vulnerabilities': [
        {
            'cve': {
                'id': 'CVE-2021-41773',
                'descriptions': [{'lang': 'en', 'value': 'A flaw was found in Apache HTTP Server 2.4.49.'}],
                'metrics': {
                    'cvssMetricV31': [
                        {'cvssData': {'baseScore': 9.8, 'baseSeverity': 'CRITICAL'}}
                    ]
                },
            }
        },
        {
            'cve': {
                'id': 'CVE-2021-40438',
                'descriptions': [{'lang': 'en', 'value': 'A crafted request uri-path can cause mod_proxy.'}],
                'metrics': {
                    'cvssMetricV31': [
                        {'cvssData': {'baseScore': 9.0, 'baseSeverity': 'CRITICAL'}}
                    ]
                },
            }
        },
    ]
}

NVD_EMPTY = {'vulnerabilities': []}

NVD_V2_ONLY = {
    'vulnerabilities': [
        {
            'cve': {
                'id': 'CVE-2019-0001',
                'descriptions': [{'lang': 'en', 'value': 'Old vulnerability with CVSSv2 only.'}],
                'metrics': {
                    'cvssMetricV2': [
                        {'cvssData': {'baseScore': 7.5}, 'baseSeverity': 'HIGH'}
                    ]
                },
            }
        }
    ]
}


def _mock_resp(data: dict, status_code: int = 200) -> MagicMock:
    m = MagicMock()
    m.status_code = status_code
    m.json.return_value = data
    m.raise_for_status = MagicMock()
    return m


def test_lookup_cves_returns_results_sorted_by_score_descending():
    with patch('cve.requests.get', return_value=_mock_resp(NVD_TWO_CVES)), \
         patch('cve._wait_for_rate_limit'):
        result = lookup_cves('cpe:/a:apache:http_server:2.4.49')

    assert len(result) == 2
    assert result[0].cve_id == 'CVE-2021-41773'
    assert result[0].cvss_score == 9.8
    assert result[0].severity == 'CRITICAL'
    assert result[1].cve_id == 'CVE-2021-40438'
    assert result[1].cvss_score == 9.0


def test_lookup_cves_returns_empty_on_no_vulnerabilities():
    with patch('cve.requests.get', return_value=_mock_resp(NVD_EMPTY)), \
         patch('cve._wait_for_rate_limit'):
        result = lookup_cves('cpe:/a:unknown:product:1.0')

    assert result == []


def test_lookup_cves_sends_api_key_header():
    mock_get = MagicMock(return_value=_mock_resp(NVD_EMPTY))
    with patch('cve.requests.get', mock_get), \
         patch('cve._wait_for_rate_limit'):
        lookup_cves('cpe:/a:test:test:1.0', api_key='my-key')

    assert mock_get.call_args.kwargs['headers']['apiKey'] == 'my-key'


def test_lookup_cves_sends_no_api_key_header_when_none():
    mock_get = MagicMock(return_value=_mock_resp(NVD_EMPTY))
    with patch('cve.requests.get', mock_get), \
         patch('cve._wait_for_rate_limit'):
        lookup_cves('cpe:/a:test:test:1.0', api_key=None)

    assert 'apiKey' not in mock_get.call_args.kwargs['headers']


def test_lookup_cves_returns_empty_on_request_exception():
    with patch('cve.requests.get', side_effect=req.RequestException('timeout')), \
         patch('cve._wait_for_rate_limit'):
        result = lookup_cves('cpe:/a:test:test:1.0')

    assert result == []


def test_lookup_cves_handles_cvssv2_metrics():
    with patch('cve.requests.get', return_value=_mock_resp(NVD_V2_ONLY)), \
         patch('cve._wait_for_rate_limit'):
        result = lookup_cves('cpe:/a:vendor:product:1.0')

    assert len(result) == 1
    assert result[0].cvss_score == 7.5
    assert result[0].severity == 'HIGH'


def test_lookup_cves_retries_once_on_429():
    mock_get = MagicMock(side_effect=[
        _mock_resp({}, status_code=429),
        _mock_resp(NVD_EMPTY),
    ])
    with patch('cve.requests.get', mock_get), \
         patch('cve._wait_for_rate_limit'), \
         patch('cve.time.sleep') as mock_sleep:
        result = lookup_cves('cpe:/a:test:test:1.0')

    assert mock_get.call_count == 2
    assert result == []
    mock_sleep.assert_called_once_with(30)
