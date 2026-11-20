"""Train on historical URLs and validate/test on successive disjoint PhreshPhish periods."""
import argparse
import csv
import json
import re
from collections import Counter
from pathlib import Path

import numpy as np
import pyarrow.parquet as pq
from sklearn.ensemble import RandomForestClassifier

from detector import ROOT, classify, lexical_score, scan_brand_features, scan_url_features, score, url_features
from page_features import brand_features, split_address
from train import bucket, domain, export_tree, metrics, train_lexical
from train_pages import cutoff

HARD = {'login': re.compile(r'login|sign[-_]?in|auth', re.I),
        'payment': re.compile(r'checkout|payment|billing|/pay(?:/|$)', re.I),
        'recovery': re.compile(r'reset|recover|forgot|password', re.I)}


def tagged(address):
    p = split_address(address)
    return [k for k, rx in HARD.items() if rx.search(p.netloc + p.path)]


def pages(paths):
    for path in paths:
        for row in pq.read_table(path, columns=['date', 'url', 'label']).to_pylist():
            yield str(row['date'])[:10], row['url'].strip(), {'phish': 1, 'benign': 0}[row['label']]


def run(args):
    rows, exposed = {}, set()
    def add(address, label, source):
        if address in rows:
            if rows[address][0] != label:
                rows[address] = (None, source)
        else:
            rows[address] = (label, source)

    with open(args.gram, encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            address = row['url'].strip()
            sample = bucket(address)
            if sample >= 96:
                continue
            try:
                group = domain(address)
                if bucket(group) >= 51:
                    exposed.add(group)  # All possible v2 development domains.
                if sample < 9 or (row['label'] == 'benign' and tagged(address)):
                    add(address, {'benign': 0, 'malicious': 1}[row['label']], 'GramBeddings')
            except (ValueError, AttributeError):
                continue
    for label, path in enumerate(args.ebbu):
        for item in json.loads(Path(path).read_text(encoding='utf-8-sig')):
            address = item.strip()
            try:
                if bucket(address) < 40 or (label == 0 and tagged(address)):
                    add(address, label, 'Ebbu2017')
            except ValueError:
                continue
    for date, address, label in pages(args.train):
        if date > '2025-09-08':
            raise ValueError('Training period changed')
        add(address, label, 'PhreshPhish')

    x, y, addresses = [], [], []
    sources, hard = Counter(), Counter()
    for address, (label, source) in rows.items():
        try:
            fields = url_features(address) + brand_features(address)
            exposed.add(domain(address))
        except (ValueError, AttributeError):
            continue
        if label is not None:
            x.append(fields)
            y.append(label)
            addresses.append(address)
            sources[source] += 1
            if label == 0:
                hard.update(tagged(address))
    forest = RandomForestClassifier(n_estimators=64, max_depth=14, min_samples_leaf=3, random_state=42, n_jobs=3)
    forest.fit(x, y)
    trees = [export_tree(t.tree_) for t in forest.estimators_]
    lexical = train_lexical(addresses, y)
    def holdout(paths, start, end):
        batch, dates, groups = {}, [], set()
        for date, address, label in pages(paths):
            if not start <= date <= end:
                continue
            try:
                group = domain(address)
                if group in exposed:
                    continue
                url_features(address)
                if address in batch:
                    if batch[address] != label:
                        batch[address] = None
                    continue
            except (ValueError, AttributeError):
                continue
            groups.add(group)
            dates.append(date)
            batch[address] = label
        exposed.update(groups)
        batch = {a:l for a,l in batch.items() if l is not None}
        return batch, dict(start=min(dates), end=max(dates), domains=len(groups), rows=len(batch))

    val, val_meta = holdout(args.validation, '2025-09-09', '2025-10-31')
    test, test_meta = holdout(args.test, '2025-11-01', '9999-12-31')
    def scores(part):
        values = {'url': [], 'url_brand': [], 'url_mixed': []}
        for address in part:
            values['url'].append(classify('url', scan_url_features(address))['score'])
            values['url_brand'].append(classify('url_brand', scan_brand_features(address))['score'])
            fields = url_features(address) + brand_features(address)
            values['url_mixed'].append(round((score(trees, fields) + lexical_score(address, lexical))/2, 1))
        return {k:np.array(v) for k,v in values.items()}, np.array(list(part.values()), dtype=bool)
    vs, vy = scores(val)
    ts, ty = scores(test)
    report = dict(train=dict(sources), benign_special_paths=dict(hard), validation=val_meta, test=test_meta,
                  budget_per_1000=10, arms={})
    for key in vs:
        threshold = cutoff(vs[key], vy, .01)
        hard_slices = {}
        for category in HARD:
            mask = (~ty) & np.array([category in tagged(address) for address in test])
            hard_slices[category] = dict(legitimate=int(mask.sum()), fp=int((ts[key][mask]>=threshold).sum()))
        report['arms'][key] = dict(threshold=threshold, validation=metrics(vs[key], vy, threshold),
                                   test=metrics(ts[key], ty, threshold), benign_paths=hard_slices)
    best = report['arms']['url_mixed']
    exported = dict(version='mixed-v1', trees=trees, lexical=lexical, threshold=best['threshold'],
                    medium=cutoff(vs['url_mixed'], vy, .04), train=len(y), test=len(test), **best['test'])
    for fname, obj in [('mixed_benchmark.json', report), ('url_mixed_model.json', exported)]:
        (args.output / fname).write_text(json.dumps(obj, separators=(',', ':')), encoding='utf-8')
    print(json.dumps(report), flush=True)


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--gram', required=True)
    p.add_argument('--ebbu', required=True, nargs=2)
    for key in ('train', 'validation', 'test'):
        p.add_argument('--' + key, nargs='+', required=True)
    p.add_argument('--output', type=Path, default=ROOT)
    run(p.parse_args())
