"""Measure per-file end-to-end scoring time and process peak RSS, one fresh worker per file."""
import argparse
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from statistics import median


def peak_mib():
    if os.name == 'nt':
        class Counters(ctypes.Structure):
            _fields_ = [('cb', ctypes.c_uint32), ('faults', ctypes.c_uint32)] + [
                (n, ctypes.c_size_t) for n in ('peak', 'rss', 'pp', 'p', 'pn', 'n', 'page', 'peak_page')]
        c = Counters()
        c.cb = ctypes.sizeof(c)
        if not ctypes.windll.psapi.GetProcessMemoryInfo(ctypes.c_void_p(-1), ctypes.byref(c), c.cb):
            raise ctypes.WinError()
        return c.peak / (1024**2)
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024**2 if sys.platform == 'darwin' else 1024)


def worker(args):
    if args.engine == 'ember':
        from benchmark_pe import load_ember
        extractor, model = load_ember(args.extractor, args.model)
    else:
        from detector import models, pe_features, classify
        models()
    start = time.perf_counter()
    data = args.file.read_bytes()
    if args.engine == 'ember':
        vector = extractor.feature_vector(data)
        model.predict(vector.reshape(1, -1), num_threads=1)
    else:
        classify('file', pe_features(data))
    return dict(ms=round(1000*(time.perf_counter()-start), 3), peak_rss_mib=round(peak_mib(), 2))


def main(args):
    rows = []
    for line in args.manifest.read_text(encoding='utf-8-sig').splitlines():
        path = Path(line)
        data = path.read_bytes()
        row = dict(name=path.name, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
        offset = int.from_bytes(data[60:64], 'little') + 24
        row['architecture'] = {267: 'PE32', 523: 'PE32+'}[int.from_bytes(data[offset:offset+2], 'little')]
        for engine in ('sentra', 'ember'):
            cmd = [sys.executable, __file__, '--file', str(path), '--engine', engine,
                   '--extractor', str(args.extractor), '--model', str(args.model)]
            output = subprocess.check_output(cmd, text=True)
            row[engine] = json.loads(output.splitlines()[-1])
        rows.append(row)
    summary = {engine: {key: median(row[engine][key] for row in rows) for key in ('ms','peak_rss_mib')}
               for engine in ('sentra','ember')}
    args.output.write_text(json.dumps(dict(medians=summary, files=rows), indent=2), encoding='utf-8')


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for arg in ('manifest','output','extractor','model','file'):
        p.add_argument('--'+arg, type=Path)
    p.add_argument('--engine', choices=('sentra','ember'))
    args = p.parse_args()
    if args.file:
        print(json.dumps(worker(args)))
    else:
        main(args)
