import json
import logging
import os
import re
import struct
import threading
import uuid
from datetime import datetime, timezone
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit
from detector import ROOT, models, pe_features, scan_brand_features, scan_mixed_features, scan_url_features
from page_features import url_observations
from service import dispatch_loop, history, initialize, lookup, submit

LIMIT = 10 * 1024 * 1024
ASSETS = {'/': ('index.html', 'text/html'), '/style.css': ('style.css', 'text/css'),
          '/app.js': ('app.js', 'text/javascript'), '/favicon.svg': ('favicon.svg', 'image/svg+xml')}


@lru_cache(maxsize=1)
def benchmarks():
    def read(name):
        return json.loads((ROOT/name).read_text(encoding='utf-8'))
    files = {}
    for arch in ('win32','win64'):
        data = read(arch+'_benchmark.json')
        files[arch] = {engine: data[engine]['test'] for engine in ('sentra','ember')}
    costs = read('pe_cost.json')
    return dict(url=read('mixed_benchmark.json'), files=files, cost=costs['medians'], cost_files=len(costs['files']))


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(30)

    def reply(self, status, body, mime='application/json', location=None):
        if not isinstance(body, bytes):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header('Content-Type', mime + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        if location:
            self.send_header('Location', location)
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
            return self.reply(200, {k:{a:b for a,b in v.items() if a not in ('trees', 'lexical')} for k,v in models().items()})
        if path == '/api/benchmarks':
            return self.reply(200, benchmarks())
        if path == '/api/scans' or re.fullmatch(r'/api/scans/[0-9a-f]{32}', path):
            try:
                if path == '/api/scans':
                    return self.reply(200, history())
                report = lookup(path.rsplit('/', 1)[1])
                return self.reply(200, report) if report else self.reply(404, {'error': 'Проверка не найдена.'})
            except Exception:
                logging.exception('History unavailable')
                return self.reply(503, {'error': 'Журнал временно недоступен.'})
        self.reply(404, {'error': 'Ресурс не найден.'})

    def do_POST(self):
        if self.path not in ('/api/scans/url', '/api/scans/file'):
            return self.reply(404, {'error': 'Ресурс не найден.'})
        kind = self.path.rsplit('/', 1)[1]
        model_key = kind
        if self.headers.get_content_type() != ('application/octet-stream' if kind == 'file' else 'application/json'):
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
                profile = payload.get('profile', 'default') if isinstance(payload, dict) else 'default'
                profiles = {'default': ('url', scan_url_features), 'brand': ('url_brand', scan_brand_features),
                            'mixed': ('url_mixed', scan_mixed_features)}
                if not isinstance(profile, str) or profile not in profiles:
                    return self.reply(400, {'error': 'Неизвестный профиль URL-модели.'})
                model_key, extract = profiles[profile]
                features = extract(url)
                name = urlsplit(url if '://' in url else 'https://' + url).hostname
                observations = url_observations(url)
            else:
                features = pe_features(data)
                offset = struct.unpack_from('<I', data, 60)[0] + 24
                observations = {'Формат': 'PE32+' if struct.unpack_from('<H', data, offset)[0] == 523 else 'PE32',
                                'Секции': features[0], 'Размер в байтах': length}
                name = re.split(r'[/\\]', unquote(self.headers.get('X-File-Name', 'sample.exe')))[-1][:180] or 'sample.exe'
        except (ValueError, UnicodeError, RecursionError):
            errors = {'url': 'Проверьте адрес сайта.',
                      'file': 'Загрузите корректный файл Windows PE (.exe или .dll).'}
            return self.reply(400, {'error': errors[kind]})
        try:
            scan_id = uuid.uuid4().hex
            result = submit(dict(kind=kind, name=name, id=scan_id, observations=observations,
                                 created=datetime.now(timezone.utc).isoformat()), model_key, features)
        except Exception:
            logging.exception('Scan failed')
            return self.reply(503, {'error': 'Сервис анализа недоступен. Проверьте подключение к сервисам и повторите запрос.'})
        self.reply(202, result, location='/api/scans/'+scan_id)


if __name__ == '__main__':
    models()
    initialize()
    threading.Thread(target=dispatch_loop, daemon=True).start()
    host, port = os.getenv('HOST', '127.0.0.1'), int(os.getenv('PORT', '8765'))
    print('Sentra http://' + host + ':' + str(port), flush=True)
    ThreadingHTTPServer((host, port), Handler).serve_forever()
