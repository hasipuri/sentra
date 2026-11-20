import http.client
import json
import os
import struct
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest.mock import patch

from app import Handler, ThreadingHTTPServer
from service import TABLE, connect


class ScannerAPI(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        env = patch.dict(os.environ, SCAN_DB=str(Path(directory.name) / 'test.db'))
        env.start()
        self.addCleanup(env.stop)
        local = patch('service.DISTRIBUTED', False)
        local.start()
        self.addCleanup(local.stop)
        with closing(connect()) as db, db:
            db.execute(TABLE)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def request(self, method, path, body=None, mime='application/json'):
        with closing(http.client.HTTPConnection(*self.server.server_address, timeout=5)) as client:
            client.request(method, path, body, {'Content-Type': mime})
            response = client.getresponse()
            return response.status, json.load(response)

    def test_url_round_trip(self):
        status, report = self.request('POST', '/api/scans/url', '{"url":"https://example.org/?token=secret"}')
        self.assertEqual(status, 201)
        self.assertEqual(report['name'], 'example.org')
        self.assertEqual(report['model_version'], 'v2')
        self.assertIn('Оценка по фрагментам адреса', report['features'])
        _, models = self.request('GET', '/api/models')
        self.assertNotIn('lexical', models['url'])
        self.assertNotIn('trees', models['url'])
        self.assertLess(models['url']['medium'], models['url']['threshold'])
        self.assertEqual(self.request('GET', '/api/scans')[1], [report])
        self.assertNotIn('secret', str(report))

    def test_pe_headers(self):
        fixture = bytearray(1024)
        fixture[:2] = b'MZ'
        struct.pack_into('<I', fixture, 60, 128)
        fixture[128:132] = b'PE\0\0'
        struct.pack_into('<H', fixture, 134, 2)
        struct.pack_into('<H', fixture, 148, 224)
        struct.pack_into('<H', fixture, 152, 267)
        struct.pack_into('<H', fixture, 150, 0x0102)
        struct.pack_into('<I', fixture, 184, 4096)
        status, report = self.request('POST', '/api/scans/file', fixture, 'application/octet-stream')
        self.assertEqual(status, 201)
        self.assertEqual(report['features']['NumberOfSections'], 2)
        self.assertEqual(report['features']['Characteristics'], 0x0102)
        self.assertEqual(report['features']['SectionAlignment'], 4096)
        self.assertIn(report['level'], ('low', 'medium', 'high'))

    def test_brand_profile(self):
        status, report = self.request('POST', '/api/scans/url', json.dumps({
            'url': 'https://paypal.example.co.uk/google/?token=secret', 'profile': 'brand'}))
        self.assertEqual(status, 201)
        self.assertEqual(report['kind'], 'url')
        self.assertEqual(report['model_version'], 'url-brand-v1')
        self.assertEqual(report['features']['Бренды в поддомене'], 1)
        self.assertEqual(report['features']['Бренды в имени домена'], 0)
        self.assertEqual(report['features']['Бренды в пути'], 1)
        self.assertNotIn('secret', str(report))
        self.assertEqual(self.request('GET', '/api/scans')[1], [report])
        self.assertNotIn('trees', self.request('GET', '/api/models')[1]['url_brand'])
        self.assertEqual(self.request('POST', '/api/scans/url', '{"url":"example.org","profile":"invalid"}')[0], 400)

    def test_invalid_objects_leave_no_history(self):
        for payload in ('[]', 'bad json', '{"url":"file:///invalid"}', '{"url":"https://invalid.test:abc"}'):
            self.assertEqual(self.request('POST', '/api/scans/url', payload)[0], 400)
        self.assertEqual(self.request('POST', '/api/scans/file', b'MZ', 'application/octet-stream')[0], 400)
        self.assertEqual(self.request('GET', '/api/scans')[1], [])


if __name__ == '__main__':
    unittest.main()
