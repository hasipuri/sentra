import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path

from detector import ROOT, classify

DISTRIBUTED = bool(os.getenv('DATABASE_URL'))
TABLE = 'CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created TEXT NOT NULL, report TEXT NOT NULL)'


def connect():
    if DISTRIBUTED:
        import psycopg
        return psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=5)
    path = Path(os.getenv('SCAN_DB', str(ROOT / 'data' / 'scans.db')))
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path, timeout=8)


def store(report):
    params = '%s,%s,%s' if DISTRIBUTED else '?,?,?'
    with closing(connect()) as db, db:
        db.execute('INSERT INTO scans VALUES (' + params + ')', (report['id'], report['created'], json.dumps(report)))
    if DISTRIBUTED:
        from worker import emit_event
        try:
            emit_event.apply_async(args=[report['id'], report['kind'], report['level']], retry=False)
        except Exception:
            import logging
            logging.exception('Audit event could not be queued')


def history():
    with closing(connect()) as db:
        return [json.loads(r[0]) for r in db.execute('SELECT report FROM scans ORDER BY created DESC LIMIT 100').fetchall()]


def analyze(kind, features):
    if DISTRIBUTED:
        from worker import analyze_job
        return analyze_job.delay(kind, features).get(timeout=20)
    return classify(kind, features)
