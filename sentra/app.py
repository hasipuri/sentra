import json
import logging
import os
import re
import uuid
from contextlib import closing
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
from detector import ROOT, models, pe_features, url_features
from service import TABLE, analyze, connect, history, store

LIMIT = 10 * 1024 * 1024
ASSETS = {'/': ('index.html', 'text/html'), '/style.css': ('style.css', 'text/css'),
          '/app.js': ('app.js', 'text/javascript'), '/favicon.svg': ('favicon.svg', 'image/svg+xml')}


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def reply(self, status, body, mime='application/json'):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Security-Policy', "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ASSETS:
            name, mime = ASSETS[path]
            return self.reply(200, (ROOT / 'web' / name).read_bytes(), mime)
        if path == '/api/models':
            return self.reply(200, {k:{a:b for a,b in v.items() if a != 'trees'} for k,v in models().items()})
        if path == '/api/scans':
            try:
                return self.reply(200, history())
            except Exception:
                logging.exception('History unavailable')
                return self.reply(503, {'error': 'Журнал временно недоступен.'})
        self.reply(404, {'error': 'Ресурс не найден.'})

    def do_POST(self):
        if self.path not in ('/api/scans/url', '/api/scans/file'):
            return self.reply(404, {'error': 'Ресурс не найден.'})
        kind = self.path.rsplit('/', 1)[1]
        if self.headers.get_content_type() != ('application/json' if kind == 'url' else 'application/octet-stream'):
            return self.reply(415, {'error': 'Неподдерживаемый тип данных.'})
        try:
            length = int(self.headers.get('Content-Length', 0))
            if length > (16384 if kind == 'url' else LIMIT):
                return self.reply(413, {'error': 'Превышен допустимый размер.'})
            if length <= 0:
                raise ValueError('Нет данных для проверки.')
            data = self.rfile.read(length)
            if len(data) != length:
                raise ValueError('Получены неполные данные.')
            if kind == 'url':
                payload = json.loads(data)
                url = payload.get('url') if isinstance(payload, dict) else None
                features = url_features(url)
                name = urlsplit(url if '://' in url else 'https://' + url).hostname
            else:
                features = pe_features(data)
                name = re.split(r'[/\\]', unquote(self.headers.get('X-File-Name', 'sample.exe')))[-1][:180] or 'sample.exe'
        except (ValueError, UnicodeError, RecursionError):
            return self.reply(400, {'error': 'Проверьте адрес сайта.' if kind == 'url' else 'Загрузите корректный файл Windows PE (.exe или .dll).'})
        try:
            result = analyze(kind, features)
            result.update(kind=kind, name=name, id=uuid.uuid4().hex,
                          created=datetime.now(timezone.utc).isoformat())
            store(result)
        except Exception:
            logging.exception('Scan failed')
            return self.reply(503, {'error': 'Сервис анализа недоступен. Проверьте подключение к сервисам и повторите запрос.'})
        self.reply(201, result)


if __name__ == '__main__':
    models()
    with closing(connect()) as db, db:
        db.execute(TABLE)
    host, port = os.getenv('HOST', '127.0.0.1'), int(os.getenv('PORT', '8765'))
    print('Sentra http://' + host + ':' + str(port), flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
