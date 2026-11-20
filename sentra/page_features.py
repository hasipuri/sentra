"""Offline URL and saved-HTML features. No outbound requests."""
import ipaddress
from collections import Counter
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

HTML_WINDOW = 65536
MAX_HTML_BYTES = 1024 * 1024
BRANDS = ('paypal', 'google', 'microsoft', 'apple', 'facebook', 'amazon',
          'netflix', 'dropbox', 'yahoo', 'docusign', 'adobe', 'instagram',
          'yandex', 'sber', 'tinkoff', 'gosuslugi', 'github', 'linkedin')
BRAND_FIELDS = ['Бренды в имени домена', 'Бренды в поддомене', 'Бренды в пути',
                'Имя домена совпадает с названием бренда']
HTML_FIELDS = ['Формы', 'Поля пароля', 'Поля ввода почты', 'Скрытые поля',
               'Формы POST', 'Формы с внешним адресом', 'Внешняя отправка пароля',
               'Встроенные фреймы', 'Перенаправления meta refresh']


@lru_cache(maxsize=1)
def suffix_rules():
    rules = set()
    path = Path(__file__).with_name('public_suffix_list.dat')
    for line in path.read_text(encoding='utf-8').splitlines():
        if line and not line.startswith('//'):
            rules.add(line.encode('idna').decode().lower())
    return rules


@lru_cache(maxsize=16384)
def host_parts(host):
    host = host.rstrip('.').lower().encode('idna').decode()
    try:
        ipaddress.ip_address(host)
        return host, host, ''
    except ValueError:
        pass
    labels = host.split('.')
    rules = suffix_rules()
    size = 1
    for i in range(len(labels)):
        tail = '.'.join(labels[i:])
        if '!' + tail in rules:
            size = len(labels) - i - 1
            break
        if tail in rules or (i + 1 < len(labels) and '*.' + '.'.join(labels[i+1:]) in rules):
            size = max(size, len(labels) - i)
    pos = max(0, len(labels) - size - 1)
    return '.'.join(labels[pos:]), labels[pos], '.'.join(labels[:pos])


def split_address(address):
    return urlsplit(address if '://' in address else 'https://' + address)


def brand_features(address):
    parts = split_address(address)
    _, label, sub = host_parts(parts.hostname)
    path = unquote(parts.path).lower()
    return [sum(b in text for b in BRANDS) for text in (label, sub, path)] + [int(label in BRANDS)]


def host_observations(host):
    domain, _, subdomain = host_parts(host)
    try:
        ipaddress.ip_address(domain)
        host_fact = ('Адрес узла (IP)', domain)
    except ValueError:
        host_fact = ('Имя хоста' if domain in suffix_rules() else 'Регистрируемый домен', domain)
    facts = dict([host_fact])
    if subdomain:
        facts['Поддомен'] = subdomain
    return facts


def url_observations(address):
    parts = split_address(address)
    facts = host_observations(parts.hostname)
    facts['Протокол'] = parts.scheme.upper()
    return facts


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.counts = Counter()
        self.forms = []
        self.passwords = []
        self.overrides = []
        self.current = None
        self.base = None
        self.has_markup = False

    def handle_starttag(self, tag, attrs):
        a = {k: (v or '') for k, v in attrs}
        if tag in ('html', 'head', 'body', 'title', 'p', 'a', 'div', 'form', 'input', 'main', 'script', 'meta', 'h1'):
            self.has_markup = True
        if tag == 'base' and self.base is None and 'href' in a:
            self.base = a['href']
        if tag == 'form':
            self.current = len(self.forms)
            self.forms.append((a.get('id'), a.get('action', ''), a.get('method', '').lower()))
        if tag == 'input':
            typ = a.get('type', 'text').strip().lower()
            self.counts[typ] += 1
            if typ == 'password':
                self.passwords.append((a.get('form'), self.current))
        if tag in ('button', 'input') and 'formaction' in a:
            self.overrides.append((a.get('form'), self.current, a['formaction']))
        if tag == 'iframe':
            self.counts['iframe_tags'] += 1
        if tag == 'meta' and a.get('http-equiv', '').strip().lower() == 'refresh':
            self.counts['refresh_tags'] += 1

    def handle_endtag(self, tag):
        if tag == 'form':
            self.current = None


def html_features(address, html):
    if not isinstance(html, str) or '\x00' in html[:HTML_WINDOW]:
        raise ValueError('Требуется текст HTML.')
    parser = FormParser()
    try:
        parser.feed(html[:HTML_WINDOW])
        parser.close()
    except (AssertionError, ValueError) as exc:
        raise ValueError('Не удалось прочитать HTML.') from exc
    if not parser.has_markup:
        raise ValueError('В начале файла не найдена HTML-разметка.')
    source = split_address(address)
    origin = host_parts(source.hostname)[0]
    def external(action):
        if not action.strip():
            return False
        try:
            base = urljoin(source.geturl(), parser.base or '')
            target = urlsplit(urljoin(base, action))
            return target.scheme in ('http', 'https') and bool(target.hostname) and host_parts(target.hostname)[0] != origin
        except (ValueError, UnicodeError):
            return False
    ids = {form[0]: i for i, form in enumerate(parser.forms) if form[0]}
    password_forms = {ids.get(name) if name is not None else parent for name, parent in parser.passwords}
    external_forms = {i for i, form in enumerate(parser.forms) if external(form[1])}
    for name, parent, action in parser.overrides:
        owner = ids.get(name) if name is not None else parent
        if owner is not None and external(action):
            external_forms.add(owner)
    c = parser.counts
    return [len(parser.forms), c['password'], c['email'], c['hidden'],
            sum(f[2] == 'post' for f in parser.forms), len(external_forms),
            len(external_forms & password_forms), c['iframe_tags'], c['refresh_tags']]
