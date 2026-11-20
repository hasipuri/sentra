"""Train offline. Only JSON trees are required for serving."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.linear_model import LogisticRegression
from tldextract import TLDExtract

from detector import PE_FIELDS, lexical_score, score, url_features, url_text

extract = TLDExtract(suffix_list_urls=(), cache_dir=None)


def bucket(value):
    return hashlib.sha256(value.encode()).digest()[0]


def domain(address):
    host = urlsplit(address if '://' in address else 'https://' + address).hostname
    host = host.rstrip('.').encode('idna').decode('ascii').lower()
    return extract(host).top_domain_under_public_suffix or host


def url_samples(path):
    labels = {}
    with open(path, encoding='utf-8-sig', newline='') as f:
        for row in csv.DictReader(f):
            address = row['url'].strip()
            # Stable sample to bound training cost on a laptop.
            if bucket(address) >= 96:
                continue
            label = {'benign': 0, 'malicious': 1}[row['label']]
            if labels.setdefault(address, label) != label:
                labels[address] = None
    for address, label in labels.items():
        if label is None:
            continue
        try:
            features, group = url_features(address), domain(address)
        except ValueError:
            continue
        yield features, label, group, address


def pe_samples(path):
    with open(path, newline='') as f:
        for row in csv.DictReader(f):
            features = [int(row[key]) for key in PE_FIELDS]
            # Preserve the original test partition (old 12-field fingerprint).
            yield features, int(row['class']), str(features[:12]), None


def export_tree(tree, i=0):
    if tree.children_left[i] == -1:
        counts = tree.value[i, 0]
        return round(float(counts[1] / counts.sum()), 7)
    return [int(tree.feature[i]), float(tree.threshold[i]),
            export_tree(tree, tree.children_left[i]), export_tree(tree, tree.children_right[i])]


def metrics(scores, labels, threshold):
    predicted = scores >= threshold
    return dict(tp=int(sum(predicted & labels)), fp=int(sum(predicted & ~labels)),
                fn=int(sum(~predicted & labels)), tn=int(sum(~predicted & ~labels)))


def evaluate(trees, rows, lexical=None):
    scores = [score(trees, x) for x, _, _ in rows]
    if lexical:
        scores = [round((s + lexical_score(address, lexical)) / 2, 1)
                  for s, (_, _, address) in zip(scores, rows)]
    return np.array(scores), np.array([bool(y) for _, y, _ in rows])


def train_lexical(addresses, labels):
    vect = CountVectorizer(analyzer='char', ngram_range=(3, 4), preprocessor=url_text,
                           binary=True, min_df=5, max_features=40000, dtype=np.float32)
    matrix = vect.fit_transform(addresses)
    lr = LogisticRegression(solver='liblinear', C=.25, random_state=42).fit(matrix, labels)
    return dict(intercept=float(lr.intercept_[0]), weights={
        token: round(float(lr.coef_[0, ix]), 6) for token, ix in vect.vocabulary_.items()})


def fit(records, kind, baseline):
    train, val, test = [], [], []
    exposed = set()
    for x, y, group, address in records:
        b = bucket(group)
        rows = test if b < 51 else val if b < 89 else train
        rows.append((x, y, address))
        if b >= 51:
            exposed.add(group)
    x, y, addresses = zip(*train)
    forest = RandomForestClassifier(n_estimators=40, max_depth=14, min_samples_leaf=3,
                                    n_jobs=4, random_state=42).fit(x, y)
    trees = [export_tree(est.tree_) for est in forest.estimators_]
    # Lowest threshold in the operating range meeting a fixed validation FPR budget.
    warning_budget, high_budget = (.04, .01) if kind == 'url' else (.12, .05)
    candidates = [None]
    if kind == 'url':
        candidates.append(train_lexical(addresses, y))
    best_tp = -1
    for candidate in candidates:
        scores, labels = evaluate(trees, val, candidate)
        cut = next(t for t in range(1, 102) if (scores[~labels] >= t).mean() <= high_budget)
        performance = metrics(scores, labels, cut)
        print(kind, 'validation:', 'hybrid' if candidate else 'forest', cut, performance, flush=True)
        if performance['tp'] > best_tp:
            best_tp, lexical, threshold = performance['tp'], candidate, cut
            warning = next(t for t in range(1, cut+1) if (scores[~labels] >= t).mean() <= warning_budget)
    model = dict(trees=trees, version='v2', threshold=threshold, medium=warning,
                 train=len(train), validation=len(val), test=len(test),
                 **metrics(*evaluate(trees, test, lexical), threshold))
    print(kind, 'test:', {k:v for k,v in model.items() if k != 'trees'}, flush=True)
    if lexical:
        model['lexical'] = lexical
    if baseline:
        print(kind, 'previous model, same rows:', metrics(*evaluate(baseline['trees'], test),
                                                         baseline.get('threshold', 65)), flush=True)
    return model, exposed


def external_test(paths, excluded, models):
    examples = {}
    for label, path in enumerate(paths):
        for address in json.loads(Path(path).read_text(encoding='utf-8-sig')):
            address = address.strip()
            if examples.setdefault(address, label) != label:
                examples[address] = None
    rows = []
    for address, label in examples.items():
        try:
            features = url_features(address)
            if label is not None and domain(address) not in excluded:
                rows.append((features, label, address))
        except ValueError:
            continue
    for name, model in models.items():
        print('Ebbu2017', name, len(rows), metrics(*evaluate(model['trees'], rows, model.get('lexical')), model.get('threshold', 65)))


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('gram_csv')
    p.add_argument('clamp_csv')
    p.add_argument('output', type=Path)
    p.add_argument('--baseline', type=Path)
    p.add_argument('--external', nargs=2, metavar=('BENIGN_JSON','PHISHING_JSON'))
    args = p.parse_args()
    old = json.loads(args.baseline.read_text()) if args.baseline else {}
    url, exposed = fit(url_samples(args.gram_csv), 'url', old.get('url'))
    pe, _ = fit(pe_samples(args.clamp_csv), 'file', old.get('file'))
    if args.external:
        external_test(args.external, exposed, {'v2':url, **({'baseline':old['url']} if old else {})})
    args.output.write_text(json.dumps({'url':url,'file':pe}, separators=(',', ':')), encoding='utf-8')
