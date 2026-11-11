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
        status, report = self.request('POST', '/api/scans/file', fixture, 'application/octet-stream')
        self.assertEqual(status, 201)
        self.assertEqual(report['features']['NumberOfSections'], 2)
        self.assertIn(report['level'], ('low', 'medium', 'high'))

    def test_invalid_objects_leave_no_history(self):
        for payload in ('[]', 'bad json', '{"url":"file:///invalid"}', '{"url":"https://invalid.test:abc"}'):
            self.assertEqual(self.request('POST', '/api/scans/url', payload)[0], 400)
        self.assertEqual(self.request('POST', '/api/scans/file', b'MZ', 'application/octet-stream')[0], 400)
        self.assertEqual(self.request('GET', '/api/scans')[1], [])


if __name__ == '__main__':
    unittest.main()
