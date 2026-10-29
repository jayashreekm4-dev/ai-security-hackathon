"""Brute-force login detection: three detectors compared on the same log.

  naive_minute   fixed per-minute threshold (the original rule; misses boundary splits)
  sliding_rule   exact sliding 60 s window threshold
  robust_z       statistical: median/MAD z-score of failures per 60 s window
  iforest        ML: Isolation Forest on per-window features (needs scikit-learn)

Usage:
  python detector.py auth.log
  python detector.py auth.log --labels labels.json
"""
import argparse
import json
from collections import defaultdict
from datetime import datetime

BUCKET = 30      # seconds; windows are 2 buckets (60 s) stepped every 30 s
FAIL = "FAILED"


def parse_line(line):
    """Return (epoch_seconds, ip, ok) or None for a malformed line."""
    p = line.split()
    if len(p) != 5 or p[3] != "LOGIN" or p[4] not in ("SUCCESS", FAIL):
        return None
    try:
        ts = datetime.strptime(f"{p[0]} {p[1]}", "%Y-%m-%d %H:%M:%S").timestamp()
    except ValueError:
        return None
    return ts, p[2], p[4] == "SUCCESS"


def read_events(path):
    events, bad = [], 0
    with open(path) as f:
        for line in f:
            if line.strip():
                e = parse_line(line)
                if e:
                    events.append(e)
                else:
                    bad += 1
    return events, bad


def naive_minute(events, threshold=10):
    counts = defaultdict(int)
    for ts, ip, ok in events:
        if not ok:
            counts[(ip, int(ts // 60))] += 1
    return {ip for (ip, _), c in counts.items() if c > threshold}


def sliding_rule(events, threshold=10, window=60):
    times = defaultdict(list)
    for ts, ip, ok in events:
        if not ok:
            times[ip].append(ts)
    flagged = set()
    for ip, ts in times.items():
        ts.sort()
        lo = 0
        for hi in range(len(ts)):
            while ts[hi] - ts[lo] >= window:
                lo += 1
            if hi - lo + 1 > threshold:
                flagged.add(ip)
                break
    return flagged


def build_windows(events):
    """{(ip, start_bucket): (fails, total, fail_ratio)} for overlapping 60 s windows."""
    buckets = defaultdict(lambda: [0, 0])
    for ts, ip, ok in events:
        b = buckets[(ip, int(ts // BUCKET))]
        b[1] += 1
        b[0] += not ok
    starts = {(ip, b + d) for ip, b in buckets for d in (-1, 0)}
    windows = {}
    for ip, s in starts:
        f = sum(buckets[(ip, s + k)][0] for k in (0, 1) if (ip, s + k) in buckets)
        t = sum(buckets[(ip, s + k)][1] for k in (0, 1) if (ip, s + k) in buckets)
        windows[(ip, s)] = (f, t, f / t if t else 0.0)
    return windows


def _median(xs):
    xs = sorted(xs)
    if not xs:
        return 0.0
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def robust_z(events, z_threshold=5.0):
    windows = build_windows(events)
    fails = [w[0] for w in windows.values()]
    med = _median(fails)
    mad = _median([abs(x - med) for x in fails])
    scale = max(1.4826 * mad, 1.0)  # floor: most windows have 0-1 failures, so MAD is ~0
    return {ip for (ip, _), w in windows.items() if (w[0] - med) / scale > z_threshold}


def iforest(events, contamination=0.005, seed=42):
    from sklearn.ensemble import IsolationForest
    windows = build_windows(events)
    keys = list(windows)
    X = [windows[k] for k in keys]
    med = _median([w[0] for w in windows.values()])
    pred = IsolationForest(contamination=contamination, random_state=seed).fit_predict(X)
    # only the "too many failures" side counts as an attack
    return {k[0] for k, p, w in zip(keys, pred, X) if p == -1 and w[0] > med}


def score(flagged, attackers, all_ips):
    tp = len(flagged & attackers)
    fp = len(flagged - attackers)
    fn = len(attackers - flagged)
    prec = tp / (tp + fp) if tp + fp else 1.0
    rec = tp / (tp + fn) if tp + fn else 1.0
    return tp, fp, fn, prec, rec


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log", nargs="?", default="auth.log", help="path to the log file")
    ap.add_argument("--labels", help="labels.json for precision/recall")
    a = ap.parse_args()

    try:
        events, bad = read_events(a.log)
    except FileNotFoundError:
        print(f"Log file not found: {a.log}")
        return
    print(f"{len(events)} events parsed, {bad} malformed lines skipped\n")
    if not events:
        print("No valid lines found. Each line must look like: YYYY-MM-DD HH:MM:SS IP LOGIN FAILED")
        return

    detectors = {"naive_minute": naive_minute, "sliding_rule": sliding_rule, "robust_z": robust_z}
    try:
        import sklearn  # noqa: F401
        detectors["iforest"] = iforest
    except ImportError:
        print("scikit-learn not installed: skipping iforest\n")

    attackers = None
    if a.labels:
        attackers = set(json.load(open(a.labels))["attackers"])
        print(f"{'detector':14} {'TP':>3} {'FP':>3} {'FN':>3} {'precision':>9} {'recall':>7}")
    all_ips = {ip for _, ip, _ in events}
    for name, fn in detectors.items():
        flagged = fn(events)
        if attackers is not None:
            tp, fp, fn_, p, r = score(flagged, attackers, all_ips)
            print(f"{name:14} {tp:>3} {fp:>3} {fn_:>3} {p:>9.2f} {r:>7.2f}   flagged={sorted(flagged)}")
        else:
            print(f"{name}: {sorted(flagged) or 'no attacks found'}")


if __name__ == "__main__":
    main()
