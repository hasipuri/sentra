"""Run inside the API container. Creates one report and verifies it across services."""
import json
import os
import time
from urllib.request import Request, urlopen

import psycopg
import redis


def check():
    request = Request('http://localhost:8765/api/scans/url',
                      data=b'{"url":"https://stack-check.example.org/","profile":"brand"}',
                      headers={'Content-Type': 'application/json'})
    with urlopen(request, timeout=35) as response:
        assert response.status == 202
        report = json.load(response)
        assert response.getheader('Location') == '/api/scans/' + report['id']
    scan_id = report['id']
    assert report['status'] == 'queued'
    deadline = time.monotonic()+60
    while time.monotonic() < deadline:
        with urlopen('http://localhost:8765/api/scans/'+scan_id, timeout=5) as response:
            report = json.load(response)
        if report['status'] in ('done','failed'):
            break
        time.sleep(.25)
    assert report['status'] == 'done' and report['model_version'] == 'url-brand-v1'
    print('REST report:', scan_id, flush=True)
    with psycopg.connect(os.environ['DATABASE_URL']) as db:
        saved = db.execute('SELECT report FROM scans WHERE id=%s', (scan_id,)).fetchone()
        assert saved and json.loads(saved[0]) == report, 'PostgreSQL report mismatch'
    print('PostgreSQL: matching report')

    client = redis.Redis.from_url(os.environ['REDIS_URL'])
    deadline = time.monotonic()+8
    while True:
        result = json.loads(client.get('celery-task-meta-' + scan_id) or '{}')
        if result or time.monotonic() >= deadline:
            break
        time.sleep(.1)
    assert result.get('status') == 'SUCCESS', 'Missing successful Celery result in Redis'
    assert all(result['result'][key] == report[key] for key in ('score', 'level', 'features'))
    print('Redis: matching Celery result')

if __name__ == '__main__':
    check()
