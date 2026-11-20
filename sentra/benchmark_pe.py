"""Compare Sentra and the published EMBER2024 PE model on the same signed files.

Use the upstream thrember features.py with its matching pefile_warnings.txt.
The manifest must contain paths to files whose signatures were checked beforehand.
"""
import argparse
import hashlib
import json
import zipfile
from pathlib import Path

import lightgbm as lgb
import numpy as np
import pefile

from detector import classify, models, pe_features


def header_ranges(raw):
    """Bounds for the 18 Sentra fields recoverable from EMBER's JSON."""
    coff, opt = raw['coff'], raw['optional']
    coff_flags = sum(pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_' + name] for name in set(coff['characteristics']))
    dll_flags = sum(pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_' + name] for name in set(opt['dll_characteristics']))
    values = [coff['number_of_sections'], opt['major_linker_version'], opt['sizeof_code'],
              opt['sizeof_initialized_data'], opt['sizeof_uninitialized_data'], opt['address_of_entrypoint'],
              0, opt['major_subsystem_version'], opt['sizeof_image'], opt['sizeof_headers'],
              pefile.SUBSYSTEM_TYPE[opt['subsystem']], dll_flags, coff_flags, opt['minor_linker_version'],
              opt['section_alignment'], opt['major_operating_system_version'], opt['major_image_version'],
              opt['base_of_code']]
    ranges = [(v, v) for v in values]
    ranges[6] = (0, 2**32-1)  # FileAlignment is absent from the published feature rows.
    ranges[11] = (dll_flags, dll_flags | 0x1f)  # Reserved and legacy low bits are omitted.
    if opt['subsystem'] == 'IMAGE_SUBSYSTEM_UNKNOWN':
        ranges[10] = (0, 65535)
    return ranges


def tree_bounds(node, ranges):
    if not isinstance(node, list):
        return node, node
    index, split, left, right = node
    lo, hi = ranges[index]
    if hi <= split:
        return tree_bounds(left, ranges)
    if lo > split:
        return tree_bounds(right, ranges)
    a, b = tree_bounds(left, ranges), tree_bounds(right, ranges)
    return min(a[0], b[0]), max(a[1], b[1])


def labeled(archive, extractor, model):
    trees = models()['file']['trees']
    partitions = [[], []]
    seen = set()
    skipped = 0
    with zipfile.ZipFile(archive) as z:
        weeks = sorted(n for n in z.namelist() if n.endswith('.jsonl'))
        for week, name in enumerate(weeks):
            vectors, rows = [], []
            with z.open(name) as stream:
                for line in stream:
                    row = json.loads(line)
                    sha = row['sha256']
                    if int(sha[:2], 16) >= 24 or sha in seen or row['label'] not in (0, 1):
                        continue
                    seen.add(sha)
                    header = row.get('header') or {}
                    if header.get('optional', {}).get('magic') not in (267, 523) or not 1 <= header['coff']['number_of_sections'] <= 96:
                        skipped += 1
                        continue
                    ranges = header_ranges(header)
                    bounds = np.array([tree_bounds(t, ranges) for t in trees])
                    lo, hi = [round(100*float(sum(col))/len(trees), 1) for col in bounds.T]
                    vectors.append(extractor.process_raw_features(row))
                    rows.append((row['label'], lo, hi))
            predictions = model.predict(np.stack(vectors), num_threads=1)
            partitions[int(week >= len(weeks)//2)].extend([*row, p] for row, p in zip(rows, predictions))
    val, test = map(np.array, partitions)
    result = dict(weeks=weeks, calibration_rows=len(val), test_rows=len(test), excluded_headers=skipped,
                  sample='first SHA-256 byte < 24', validation_fpr_budget=.05)
    for name, low, high in [('sentra', 1, 2), ('ember', 3, 3)]:
        neg = np.sort(val[val[:, 0] == 0, high])[::-1]
        threshold = float(np.nextafter(neg[int(len(neg)*.05)], np.inf))
        counts = {}
        for key, data in [('validation', val), ('test', test)]:
            y = data[:, 0].astype(bool)
            counts[key] = dict(positive=int(y.sum()), negative=int((~y).sum()),
                               tp_range=[int((data[y, c] >= threshold).sum()) for c in (low, high)],
                               fp_range=[int((data[~y, c] >= threshold).sum()) for c in (low, high)])
        result[name] = dict(threshold=threshold, **counts)
    return result


def main(args):
    # The upstream module uses modern type annotations; defer them on Python 3.9.
    namespace = {'__file__': str(args.extractor), '__name__': 'ember_features'}
    source = 'from __future__ import annotations\n' + args.extractor.read_text(encoding='utf-8')
    exec(compile(source, str(args.extractor), 'exec'), namespace)
    extractor = namespace['PEFeatureExtractor']()
    model = lgb.Booster(model_file=str(args.model))
    if model.num_feature() != extractor.dim:
        raise ValueError('The EMBER model and extractor dimensions differ.')
    if args.archive:
        report = labeled(args.archive, extractor, model)
        args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
        return
    items = []
    for line in args.manifest.read_text(encoding='utf-8-sig').splitlines():
        path = Path(line)
        data = path.read_bytes()
        sentra = classify('file', pe_features(data))
        vector = extractor.feature_vector(data)
        prob = float(model.predict(vector.reshape(1, -1), num_threads=1)[0])
        items.append(dict(name=path.name, sha256=hashlib.sha256(data).hexdigest(), sentra=sentra['score'], ember=prob))
    if not items:
        raise ValueError('No files selected')
    threshold = models()['file']['threshold']
    report = dict(files=len(items), sentra_threshold=threshold, ember_threshold=.5,
                  sentra_high=sum(r['sentra'] >= threshold for r in items),
                  ember_high=sum(r['ember'] >= .5 for r in items),
                  extractor_sha256=hashlib.sha256(args.extractor.read_bytes()).hexdigest(),
                  model_sha256=hashlib.sha256(args.model.read_bytes()).hexdigest(), items=items)
    args.output.write_text(json.dumps(report, indent=2), encoding='utf-8')
    print({k: v for k, v in report.items() if k != 'items'})


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('extractor', 'model', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--archive', type=Path)
    source.add_argument('--manifest', type=Path)
    main(parser.parse_args())
