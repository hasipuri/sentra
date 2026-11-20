"""Compare URL and static HTML on PhreshPhish and export the URL brand model."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier

from detector import ROOT, URL_FIELDS, classify, scan_url_features, score
from page_features import BRAND_FIELDS, HTML_FIELDS, HTML_WINDOW, MAX_HTML_BYTES, brand_features, host_parts, html_features, split_address
from train import bucket, domain, export_tree, metrics, url_samples


def records(paths, excluded_domains, seen, stats):
    for path in paths:
        for batch in pq.ParquetFile(path).iter_batches(batch_size=32, columns=['url', 'label', 'html']):
            for row in batch.to_pylist():
                address, html = row['url'], row['html']
                stats['read'] += 1
                if not html or len(html.encode('utf-8')) > MAX_HTML_BYTES:
                    stats['size_or_empty'] += 1
                    continue
                digest = hashlib.sha256(html[:HTML_WINDOW].encode()).digest()
                if digest in seen or address in seen:
                    stats['duplicate'] += 1
                    continue
                try:
                    features = scan_url_features(address)
                    group = host_parts(split_address(address).hostname)[0]
                    if group in excluded_domains:
                        stats['known_domain'] += 1
                        continue
                    extra = brand_features(address) + html_features(address, html)
                except (ValueError, UnicodeError):
                    stats['unusable'] += 1
                    continue
                seen.update((digest, address))
                label = {'benign': 0, 'phish': 1}[row['label']]
                yield features + extra, label, group, classify('url', features)['score']


def cutoff(scores, labels, budget):
    # Smallest achievable threshold that meets the false-positive budget.
    candidates = np.unique(np.append(scores, 100.1))
    negatives = scores[~labels]
    return next(float(t) for t in candidates if (negatives >= t).mean() <= budget)


def external_checks(args, development, candidate):
    from detector import LOGIN_WORDS, lexical_score, models, url_features
    old = models()['url']
    dev_domains = {r[2] for r in development}
    gram_exposed = set()
    summary = {}

    def measure(dataset, address, fields, label):
        fields = fields + [lexical_score(address, old['lexical'])]
        tests = [(classify('url', fields)['score'], old['threshold']),
                 (score(candidate['trees'], fields + brand_features(address)), candidate['threshold'])]
        for key, (value, cut) in zip(('v2', 'url_brand'), tests):
            result = summary.setdefault(dataset, {}).setdefault(key, dict(tp=0, fp=0, tn=0, fn=0))
            result[('tp' if label else 'fp') if value >= cut else ('fn' if label else 'tn')] += 1

    for fields, label, group, address in url_samples(args.gram):
        if bucket(group) >= 51:
            gram_exposed.add(group)
        elif host_parts(split_address(address).hostname)[0] not in dev_domains:
            measure('GramBeddings', address, fields, label)
    examples = {}
    for label, path in enumerate(args.ebbu):
        for entry in json.loads(Path(path).read_text(encoding='utf-8-sig')):
            address = entry.strip()
            if examples.setdefault(address, label) != label:
                examples[address] = None
    for address, label in examples.items():
        try:
            if label is None or domain(address) in gram_exposed:
                continue
            parts = split_address(address)
            if host_parts(parts.hostname)[0] in dev_domains:
                continue
            fields = url_features(address)
        except (AttributeError, ValueError):
            continue
        measure('Ebbu2017', address, fields, label)
        if label == 0 and LOGIN_WORDS.search(parts.hostname + parts.path):
            measure('Ebbu2017_benign_login_terms', address, fields, label)
    return summary


def run(args):
    counts = {'development': Counter(), 'test': Counter()}
    seen = set()
    development = list(records(args.train, set(), seen, counts['development']))
    train = [r for r in development if bucket(r[2]) < 200]
    val = [r for r in development if bucket(r[2]) >= 200]
    test = list(records(args.test, {r[2] for r in development}, seen, counts['test']))
    print('Partitions:', len(train), len(val), len(test), flush=True)
    result = dict(source='phreshphish/phreshphish@eca603e', files={
        'train': [Path(p).name for p in args.train], 'test': [Path(p).name for p in args.test]},
        exclusions=counts, budgets={'high': 0.01, 'medium': 0.04}, arms={})
    for label, part in [('train', train), ('validation', val), ('test', test)]:
        result[label] = dict(rows=len(part), positives=sum(r[1] for r in part), domains=len({r[2] for r in part}))
    base = len(URL_FIELDS) + 1
    for arm, width in [('v2', 0), ('url', base), ('url_brand', base+len(BRAND_FIELDS)),
                       ('url_brand_html', base+len(BRAND_FIELDS)+len(HTML_FIELDS))]:
        trees = None
        if width:
            rf = RandomForestClassifier(n_estimators=64, max_depth=8, min_samples_leaf=5,
                                        random_state=42, n_jobs=2, class_weight='balanced')
            rf.fit([r[0][:width] for r in train], [r[1] for r in train])
            trees = [export_tree(t.tree_) for t in rf.estimators_]
        def evaluate(rows):
            return (np.array([score(trees, r[0]) if trees else r[3] for r in rows]),
                    np.array([bool(r[1]) for r in rows]))
        v, yv = evaluate(val)
        t, yt = evaluate(test)
        high, medium = [cutoff(v, yv, b) for b in (0.01, 0.04)]
        result['arms'][arm] = {'threshold': high, 'medium': medium,
                               'validation': metrics(v, yv, high), 'test': metrics(t, yt, high),
                               'validation_medium': metrics(v, yv, medium), 'test_medium': metrics(t, yt, medium)}
        password = base + len(BRAND_FIELDS) + HTML_FIELDS.index('Поля пароля')
        legit_login = (~yt) & np.array([r[0][password] > 0 for r in test])
        result['arms'][arm]['benign_password_pages'] = {
            'rows': int(legit_login.sum()), 'fp': int((t[legit_login] >= high).sum())}
        if arm == 'v2':
            from detector import models
            result['v2_deployed_threshold'] = metrics(t, yt, models()['url']['threshold'])
        if arm == 'url_brand':
            exported = dict(trees=trees, version='url-brand-v1', train=len(train), test=len(test),
                            threshold=high, medium=medium, **metrics(t, yt, high))
    if args.gram and args.ebbu:
        result['external_at_deployed_thresholds'] = external_checks(args, development, exported)
    (args.output / 'page_benchmark.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    (args.output / 'url_brand_model.json').write_text(json.dumps(exported, separators=(',', ':')), encoding='utf-8')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--train', nargs='+', required=True)
    p.add_argument('--test', nargs='+', required=True)
    p.add_argument('--output', type=Path, default=ROOT)
    p.add_argument('--gram', type=Path)
    p.add_argument('--ebbu', nargs=2, metavar=('BENIGN_JSON', 'PHISHING_JSON'))
    run(p.parse_args())
