"""Static features shared by training and the REST service."""
import ipaddress
import json
import re
import struct
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
URL_FIELDS = ['Длина адреса', 'Длина имени хоста', 'Число точек в хосте',
              'Цифры в хосте', 'Дефисы в хосте', 'Сегменты пути',
              'Длина строки запроса', 'IP вместо домена', 'Символ @', 'Кодирование %']
PE_FIELDS = ['NumberOfSections', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
             'SizeOfUninitializedData', 'AddressOfEntryPoint', 'FileAlignment',
             'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'Subsystem', 'DllCharacteristics']


def url_features(value):
    if not isinstance(value, str) or len(value) > 4096 or not value or re.search(r'[\s\\\x00-\x1f]', value):
        raise ValueError('Введите корректный HTTP(S)-адрес длиной до 4096 символов.')
    url = urlsplit(value if '://' in value else 'https://' + value)
    host = url.hostname or ''
    if url.scheme not in ('http', 'https') or not host:
        raise ValueError('Укажите адрес сайта с протоколом HTTP или HTTPS.')
    _ = url.port
    try:
        ipaddress.ip_address(host)
        ip = 1
    except ValueError:
        ip = 0
        labels = host.rstrip('.').encode('idna').decode().split('.')
        if len(labels) < 2 or not all(re.fullmatch(r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?', s) for s in labels):
            raise ValueError('Проверьте доменное имя.')
    return [len(url.netloc + url.path + url.query), len(host), host.count('.'),
            sum(c.isdigit() for c in host), host.count('-'), len(url.path.strip('/').split('/')) if url.path.strip('/') else 0,
            len(url.query), ip, int('@' in url.netloc), value.count('%')]


def pe_features(data):
    error = ValueError('Нужен корректный исполняемый файл Windows в формате PE.')
    if len(data) < 64 or data[:2] != b'MZ':
        raise error
    pe = struct.unpack_from('<I', data, 60)[0]
    opt = pe + 24
    if pe < 64 or opt + 72 > len(data) or data[pe:pe+4] != b'PE\0\0':
        raise error
    count = struct.unpack_from('<H', data, pe + 6)[0]
    size = struct.unpack_from('<H', data, pe + 20)[0]
    if not 1 <= count <= 96 or size < 72 or opt + size + 40 * count > len(data) or struct.unpack_from('<H', data, opt)[0] not in (267, 523):
        raise error
    return [count, data[opt+2]] + [struct.unpack_from(fmt, data, opt + offset)[0] for fmt, offset in
                                 [('<I', 4), ('<I', 8), ('<I', 12), ('<I', 16), ('<I', 36),
                                  ('<H', 48), ('<I', 56), ('<I', 60), ('<H', 68), ('<H', 70)]]


@lru_cache()
def models():
    return json.loads((ROOT / 'models.json').read_text(encoding='utf-8'))


def score(trees, features):
    total = 0
    for node in trees:
        while isinstance(node, list):
            index, split, left, right = node
            node = left if features[index] <= split else right
        total += node
    return round(100 * total / len(trees), 1)


def classify(kind, features):
    value = score(models()[kind]['trees'], features)
    return dict(score=value, level='high' if value >= 65 else 'medium' if value >= 35 else 'low',
                features=dict(zip(URL_FIELDS if kind == 'url' else PE_FIELDS, features)))
