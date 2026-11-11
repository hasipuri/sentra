"""Rebuild compact randomized tree ensembles from PhiUSIIL (ZIP) and ClaMP (CSV)."""
import csv
import hashlib
import io
import json
import random
import sys
import zipfile
from urllib.parse import urlsplit
from detector import ROOT, PE_FIELDS, url_features, score

rng = random.Random(42)


def tree(rows, depth):
    pos = sum(y for x, y in rows)
    if depth == 0 or len(rows) < 24 or pos in (0, len(rows)):
        return round((pos + 1) / (len(rows) + 2), 5)
    best = None
    for i in rng.sample(range(len(rows[0][0])), 4):
        for cut in {rng.choice(rows)[0][i] for _ in range(5)}:
            lo = [r for r in rows if r[0][i] <= cut]
            hi = [r for r in rows if r[0][i] > cut]
            if min(len(lo), len(hi)) < 6:
                continue
            goodness = sum(sum(y for x, y in side)**2 / len(side) for side in (lo, hi))
            if best is None or goodness > best[0]:
                best = goodness, i, cut, lo, hi
    if best is None:
        return round((pos + 1) / (len(rows) + 2), 5)
    _, i, cut, lo, hi = best
    return [i, cut, tree(lo, depth-1), tree(hi, depth-1)]


def train(records):
    train_set, test = [], []
    for features, label, group in records:
        bucket = hashlib.sha256(group.encode()).digest()[0]
        (test if bucket < 51 else train_set).append((features, label))
    trees = [tree(rng.choices(train_set, k=min(3200, len(train_set))), 7) for _ in range(17)]
    tp = fp = fn = tn = 0
    for x, y in test:
        pred = score(trees, x) >= 65
        tp += pred and y == 1
        fp += pred and y == 0
        tn += not pred and y == 0
        fn += not pred and y == 1
    return dict(trees=trees, train=len(train_set), test=len(test), tp=tp, fp=fp, tn=tn, fn=fn)


def urls(path):
    seen = set()
    with zipfile.ZipFile(path) as archive, archive.open(archive.namelist()[0]) as f:
        for row in csv.DictReader(io.TextIOWrapper(f, encoding='utf-8-sig')):
            address = row['URL'].strip()
            if address in seen:
                continue
            try:
                features = url_features(address)
            except (ValueError, UnicodeError):
                continue
            seen.add(address)
            yield features, 1-int(row['label']), urlsplit(address).hostname or address


if __name__ == '__main__':
    result = {'url': train(urls(sys.argv[1]))}
    with open(sys.argv[2], newline='') as f:
        records = [(list(map(int, [r[k] for k in PE_FIELDS])), int(r['class'])) for r in csv.DictReader(f)]
    result['file'] = train((x, y, str(x)) for x, y in records)
    (ROOT / 'models.json').write_text(json.dumps(result, separators=(',', ':')), encoding='utf-8')
    for name, model in result.items():
        print(name, {k:v for k,v in model.items() if k != 'trees'})
