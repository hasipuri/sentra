"""Static features shared by training and the REST service."""
import ipaddress
import json
import math
import re
import struct
from collections import Counter
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit
from page_features import BRAND_FIELDS, brand_features

ROOT = Path(__file__).resolve().parent
URL_FIELDS = ['Длина адреса', 'Длина имени хоста', 'Число точек в хосте',
              'Цифры в хосте', 'Дефисы в хосте', 'Сегменты пути',
              'Длина строки запроса', 'IP вместо домена', 'Символ @', 'Кодирование %',
              'Длина метки хоста', 'Энтропия хоста', 'Цифры в пути', 'Длина сегмента пути',
              'Энтропия пути', 'Подчёркивания', 'Параметры запроса', 'Метки IDN', 'Слова входа в хосте',
              'Слова входа в пути', 'Точки в пути', 'Знаки равенства', 'Явный порт']
PE_FIELDS = ['NumberOfSections', 'MajorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData',
             'SizeOfUninitializedData', 'AddressOfEntryPoint', 'FileAlignment',
             'MajorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'Subsystem', 'DllCharacteristics',
             'Characteristics', 'MinorLinkerVersion', 'SectionAlignment', 'MajorOperatingSystemVersion',
             'MajorImageVersion', 'BaseOfCode']

LOGIN_WORDS = re.compile(r'login|signin|verify|account|secure|wallet|password|auth|confirm|update', re.I)


def entropy(text):
    return round(-sum((n/len(text)) * math.log2(n/len(text)) for n in Counter(text).values()), 3)


def url_text(address):
    # Use the same representation for pasted bare hosts and fully qualified URLs.
    return re.sub(r'^www\.', '', re.sub(r'^https?://', '', address.lower())).rstrip('/')


def lexical_score(address, lexical):
    text = url_text(address)
    grams = {text[i:i+n] for n in (3, 4) for i in range(len(text)-n+1)}
    weights = lexical['weights']
    logit = lexical['intercept'] + sum(weights.get(g, 0) for g in grams)
    return round(100 / (1 + math.exp(-max(-500, min(500, logit)))), 2)


def scan_url_features(address):
    fields = url_features(address)
    lexical = models()['url'].get('lexical')
    if lexical:
        fields.append(lexical_score(address, lexical))
    return fields


def scan_brand_features(address):
    return scan_url_features(address) + brand_features(address)


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
            len(url.query), ip, int('@' in url.netloc), value.count('%'),
            max(map(len, host.split('.'))), entropy(host), sum(c.isdigit() for c in url.path),
            max(map(len, url.path.split('/'))), entropy(url.path), value.count('_'),
            len(url.query.split('&')) if url.query else 0, host.count('xn--'),
            len(LOGIN_WORDS.findall(host)), len(LOGIN_WORDS.findall(url.path)), url.path.count('.'),
            value.count('='), int(url.port is not None)]


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
    fields = [count, data[opt+2]] + [struct.unpack_from(fmt, data, opt + offset)[0] for fmt, offset in
                                 [('<I', 4), ('<I', 8), ('<I', 12), ('<I', 16), ('<I', 36),
                                  ('<H', 48), ('<I', 56), ('<I', 60), ('<H', 68), ('<H', 70)]]
    return fields + [struct.unpack_from('<H', data, pe + 22)[0], data[opt+3],
                     struct.unpack_from('<I', data, opt+32)[0], struct.unpack_from('<H', data, opt+40)[0],
                     struct.unpack_from('<H', data, opt+44)[0], struct.unpack_from('<I', data, opt+20)[0]]


@lru_cache()
def models():
    result = json.loads((ROOT / 'models.json').read_text(encoding='utf-8'))
    brand_path = ROOT / 'url_brand_model.json'
    if brand_path.exists():
        result['url_brand'] = json.loads(brand_path.read_text(encoding='utf-8'))
    return result


def score(trees, features):
    total = 0
    for node in trees:
        while isinstance(node, list):
            index, split, left, right = node
            node = left if features[index] <= split else right
        total += node
    return round(100 * total / len(trees), 1)


def classify(kind, features):
    model = models()[kind]
    value = score(model['trees'], features)
    names = URL_FIELDS if kind == 'url' else PE_FIELDS
    if kind == 'url_brand':
        names = URL_FIELDS + ['Оценка по фрагментам адреса'] + BRAND_FIELDS
    if kind == 'url' and model.get('lexical'):
        value = round((value + features[len(URL_FIELDS)]) / 2, 1)
        names = URL_FIELDS + ['Оценка по фрагментам адреса']
    return dict(score=value, model_version=model.get('version', 'v1'),
                level='high' if value >= model.get('threshold', 65) else 'medium' if value >= model.get('medium', 35) else 'low',
                features=dict(zip(names, features)))
