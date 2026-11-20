import json
import logging
import os
import sqlite3
import threading
import time
from contextlib import closing
from functools import lru_cache
from pathlib import Path

from detector import ROOT, classify
from page_features import host_observations

DISTRIBUTED = bool(os.getenv('DATABASE_URL'))
TABLE = 'CREATE TABLE IF NOT EXISTS scans (id TEXT PRIMARY KEY, created TEXT NOT NULL, report TEXT NOT NULL)'
JOBS = '''CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY REFERENCES scans(id), model TEXT NOT NULL, features TEXT NOT NULL,
    dispatch_after DOUBLE PRECISION NOT NULL)'''
wakeup = threading.Event()


def connect():
    if DISTRIBUTED:
        import psycopg
        return psycopg.connect(os.environ['DATABASE_URL'], connect_timeout=5)
    path = Path(os.getenv('SCAN_DB', str(ROOT / 'data' / 'scans.db')))
    path.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(path, timeout=8)


def initialize():
    with closing(connect()) as db, db:
        db.execute(TABLE)
        db.execute(JOBS)


def execute(db, sql, params):
    return db.execute(sql.replace('?', '%s') if DISTRIBUTED else sql, params)


def submit(report, model, features):
    report['status'] = 'queued'
    with closing(connect()) as db, db:
        execute(db, 'INSERT INTO scans (id,created,report) VALUES (?,?,?)',
                (report['id'], report['created'], json.dumps(report)))
        execute(db, 'INSERT INTO scan_jobs (id,model,features,dispatch_after) VALUES (?,?,?,0)',
                (report['id'], model, json.dumps(features)))
    wakeup.set()
    return report


def decode(raw):
    report = json.loads(raw)
    report.setdefault('status', 'done')  # Reports written before asynchronous checks.
    if 'observations' not in report:
        if report.get('kind') == 'url' and report.get('name'):
            report['observations'] = host_observations(report['name'])
        elif report.get('kind') == 'file' and 'NumberOfSections' in report.get('features', {}):
            report['observations'] = {'Секции': report['features']['NumberOfSections']}
    return report


@lru_cache(maxsize=1)
def result_cache():
    import redis
    return redis.Redis.from_url(os.environ['REDIS_URL'], socket_connect_timeout=.5, socket_timeout=.5)


def lookup(scan_id):
    if DISTRIBUTED:
        import redis
        try:
            raw = result_cache().get('celery-task-meta-' + scan_id)
            result = json.loads(raw) if raw else {}
            cached = result.get('result')
            if result.get('status') == 'SUCCESS' and isinstance(cached, dict) and cached.get('id') == scan_id:
                return cached
        except (redis.RedisError, ValueError):
            logging.debug('Reading persistent scan after cache miss', exc_info=True)
    with closing(connect()) as db:
        row = execute(db, 'SELECT report FROM scans WHERE id=?', (scan_id,)).fetchone()
        return decode(row[0]) if row else None


def history():
    with closing(connect()) as db:
        return [decode(r[0]) for r in db.execute('SELECT report FROM scans ORDER BY created DESC LIMIT 100').fetchall()]


def locked_report(db, scan_id):
    suffix = ' FOR UPDATE' if DISTRIBUTED else ''
    if not DISTRIBUTED:
        db.execute('BEGIN IMMEDIATE')
    row = execute(db, 'SELECT report FROM scans WHERE id=?' + suffix, (scan_id,)).fetchone()
    return decode(row[0])


def run_scan(scan_id):
    with closing(connect()) as db, db:
        report = locked_report(db, scan_id)
        if report['status'] in ('done', 'failed'):
            return report
        model, raw = execute(db, 'SELECT model,features FROM scan_jobs WHERE id=?', (scan_id,)).fetchone()
        report['status'] = 'running'
        execute(db, 'UPDATE scans SET report=? WHERE id=?', (json.dumps(report), scan_id))
    try:
        result = dict(classify(model, json.loads(raw)), status='done')
    except Exception:
        logging.exception('Classification failed for %s', scan_id)
        result = dict(status='failed', error='Не удалось выполнить анализ.')
    with closing(connect()) as db, db:
        report = locked_report(db, scan_id)
        if report['status'] == 'running':
            report.update(result)
            execute(db, 'UPDATE scans SET report=? WHERE id=?', (json.dumps(report), scan_id))
            execute(db, 'DELETE FROM scan_jobs WHERE id=?', (scan_id,))
    return report


def dispatch_once():
    with closing(connect()) as db, db:
        lock = ' FOR UPDATE SKIP LOCKED' if DISTRIBUTED else ''
        if not DISTRIBUTED:
            db.execute('BEGIN IMMEDIATE')
        row = execute(db, 'SELECT id FROM scan_jobs WHERE dispatch_after<=? ORDER BY dispatch_after,id LIMIT 1'+lock,
                      (time.time(),)).fetchone()
        if not row:
            return False
        scan_id = row[0]
        if DISTRIBUTED:
            from worker import process_scan
            process_scan.apply_async(args=(scan_id,), task_id=scan_id)
        # Reclaim unfinished jobs even after broker loss. Duplicate deliveries use the same report.
        execute(db, 'UPDATE scan_jobs SET dispatch_after=? WHERE id=?', (time.time()+300, scan_id))
    if not DISTRIBUTED:
        run_scan(scan_id)
    return True


def dispatch_loop():
    while True:
        try:
            if dispatch_once():
                continue
        except Exception:
            logging.exception('Pending scan will be retried')
        wakeup.wait(1)
        wakeup.clear()
