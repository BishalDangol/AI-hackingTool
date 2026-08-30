import asyncio

from fastapi.testclient import TestClient

import backend.main as backend_main


def test_backend_imports_and_health_endpoint():
    client = TestClient(backend_main.app)
    response = client.get('/api/health')
    assert response.status_code == 200
    assert response.json()['status'] == 'healthy'


def test_scan_constructs_safe_module_command(monkeypatch):
    captured = {}

    def fake_create_task(coro):
        coro.close()
        return object()

    monkeypatch.setattr(asyncio, 'create_task', fake_create_task)
    monkeypatch.setattr(backend_main.shutil, 'which', lambda _name: None)

    client = TestClient(backend_main.app)
    response = client.post(
        '/api/scan',
        json={
            'domain': 'example.com',
            'sources': ['crtsh', 'urlscan'],
            'limit': 25,
            'dns_brute': False,
        },
    )

    assert response.status_code == 200
    job_id = response.json()['job_id']
    captured['job'] = backend_main.jobs.pop(job_id)
    backend_main.job_subscribers.pop(job_id, None)

    assert captured['job']['command'] == [
        backend_main.sys.executable,
        '-m',
        'theHarvester',
        '-d',
        'example.com',
        '-b',
        'crtsh,urlscan',
        '-l',
        '25',
    ]


def test_scan_rejects_command_injection_in_domain(monkeypatch):
    monkeypatch.setattr(asyncio, 'create_task', lambda coro: coro.close())
    client = TestClient(backend_main.app)
    response = client.post(
        '/api/scan',
        json={'domain': 'example.com;whoami', 'sources': ['crtsh']},
    )
    assert response.status_code == 400
    assert 'Invalid domain format' in response.json()['detail']


def test_shodan_asset_review_requires_explicit_authorization():
    client = TestClient(backend_main.app)
    response = client.post('/api/modules/shodan-assets/validate', json={'asset': 'example.com', 'authorized': False})
    assert response.status_code == 403
    assert 'authorization' in response.json()['detail'].lower()


def test_shodan_asset_review_accepts_authorized_domain_and_returns_safe_scope():
    client = TestClient(backend_main.app)
    response = client.post('/api/modules/shodan-assets/validate', json={'asset': 'Example.com.', 'authorized': True})
    assert response.status_code == 200
    payload = response.json()
    assert payload['asset'] == 'example.com'
    assert payload['kind'] == 'domain'
    assert payload['scope'] == 'passive Shodan metadata only'
    assert 'camera-feed access' in payload['excluded_actions']


def test_shodan_asset_review_accepts_authorized_ip():
    client = TestClient(backend_main.app)
    response = client.post('/api/modules/shodan-assets/validate', json={'asset': '192.0.2.10', 'authorized': True})
    assert response.status_code == 200
    assert response.json()['kind'] == 'ip'


def test_shodan_asset_review_rejects_invalid_asset():
    client = TestClient(backend_main.app)
    response = client.post('/api/modules/shodan-assets/validate', json={'asset': 'example.com;whoami', 'authorized': True})
    assert response.status_code == 422
    assert 'valid domain name or IP' in response.json()['detail']


def test_strix_inspired_run_views_expose_safe_structured_evidence():
    job_id = 'fixture-run'
    backend_main.jobs[job_id] = {
        'job_id': job_id,
        'domain': 'example.com',
        'sources': ['shodan'],
        'limit': 100,
        'dns_brute': False,
        'status': 'Finished',
        'command_str': 'theHarvester -d example.com -b shodan -l 100',
        'output_lines': [
            '[SUCCESS] 1 hosts found',
            'admin@example.com',
            '203.0.113.10',
            'https://example.com:443',
            'port 443 https',
            '[WARNING] Invalid response format',
        ],
        'exit_code': 0,
        'error_message': None,
        'created_at': 1.0,
        'finished_at': 2.0,
    }
    try:
        client = TestClient(backend_main.app)
        summary = client.get(f'/api/runs/{job_id}/summary')
        evidence = client.get(f'/api/runs/{job_id}/evidence')
        findings = client.get(f'/api/runs/{job_id}/findings')
        report = client.get(f'/api/runs/{job_id}/report')
        assert summary.status_code == 200
        assert summary.json()['entity_counts']['emails'] == 1
        assert evidence.json()['entities']['ips'] == ['203.0.113.10']
        assert findings.json()['severity_counts']['low'] == 1
        assert report.json()['artifacts']['text_report'].endswith(f'/api/scan/{job_id}/download')
    finally:
        backend_main.jobs.pop(job_id, None)
