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
