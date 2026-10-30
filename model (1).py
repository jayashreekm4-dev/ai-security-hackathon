"""Trainable brute-force detection model (supervised Random Forest).

  python model.py train                 train on synthetic logs, test on unseen ones, save model.joblib
  python model.py predict auth.log      load model.joblib and flag suspicious IPs in a log

Each (IP, 60 s window) becomes one sample with 3 features: failures, attempts,
failure ratio. The label is 1 if the IP is a known attacker. Training and test
logs use different random seeds, so the test score is on attacks the model never saw.
"""
import argparse
import sys

import joblib
from sklearn.ensemble import RandomForestClassifier

from detector import build_windows, naive_minute, read_events, robust_z, score, sliding_rule
from generate_logs import make_events

MODEL_PATH = "model.joblib"
TRAIN_SEEDS = range(0, 60)
TEST_SEEDS = range(1000, 1050)
MIN_ATTACK_FAILS = 5


def to_events(raw):
    return [(t.timestamp(), ip, status == "SUCCESS") for t, ip, status in raw]


def window_dataset(seeds):
    X, y = [], []
    for s in seeds:
        raw, attackers = make_events(s, randomize=True)
        for (ip, _), w in build_windows(to_events(raw)).items():
            X.append(w)
            # a window only counts as "attack" once it actually shows 5+ attack failures;
            # the first/last few attempts of an attack look identical to a typo
            y.append(int(ip in attackers and w[0] >= MIN_ATTACK_FAILS))
    return X, y


def model_detect(events, model, threshold=0.5):
    """Return {ip: highest attack probability} for IPs at or above the threshold."""
    windows = build_windows(events)
    if not windows:
        return {}
    keys = list(windows)
    probs = model.predict_proba([windows[k] for k in keys])[:, 1]
    flagged = {}
    for (ip, _), p in zip(keys, probs):
        if p >= threshold:
            flagged[ip] = max(flagged.get(ip, 0.0), float(p))
    return flagged


def train():
    X, y = window_dataset(TRAIN_SEEDS)
    print(f"Training on {len(X)} windows from {len(TRAIN_SEEDS)} logs ({sum(y)} attack windows)")
    model = RandomForestClassifier(
        n_estimators=200, min_samples_leaf=2, class_weight="balanced", random_state=42
    ).fit(X, y)
    joblib.dump(model, MODEL_PATH)
    print(f"Saved {MODEL_PATH}\n")

    detectors = {
        "naive_minute": naive_minute,
        "sliding_rule": sliding_rule,
        "robust_z": robust_z,
        "random_forest": lambda ev: set(model_detect(ev, model)),
    }
    totals = {name: [0, 0, 0] for name in detectors}
    for s in TEST_SEEDS:
        raw, attackers = make_events(s, randomize=True)
        ev = to_events(raw)
        for name, fn in detectors.items():
            tp, fp, fn_, _, _ = score(fn(ev), attackers, None)
            totals[name][0] += tp
            totals[name][1] += fp
            totals[name][2] += fn_
    print(f"Test on {len(TEST_SEEDS)} unseen logs (attacker IPs, summed over all logs)")
    print(f"{'detector':14} {'TP':>4} {'FP':>4} {'FN':>4} {'precision':>9} {'recall':>7}")
    for name, (tp, fp, fn_) in totals.items():
        p = tp / (tp + fp) if tp + fp else 1.0
        r = tp / (tp + fn_) if tp + fn_ else 1.0
        print(f"{name:14} {tp:>4} {fp:>4} {fn_:>4} {p:>9.2f} {r:>7.2f}")


def predict(path):
    try:
        model = joblib.load(MODEL_PATH)
    except FileNotFoundError:
        sys.exit(f"{MODEL_PATH} not found. Run: python model.py train")
    try:
        events, bad = read_events(path)
    except FileNotFoundError:
        sys.exit(f"Log file not found: {path}")
    print(f"{len(events)} events parsed, {bad} malformed lines skipped")
    flagged = model_detect(events, model)
    if not flagged:
        print("No attacks found")
    for ip, p in sorted(flagged.items(), key=lambda x: -x[1]):
        print(f"ATTACK: {ip}  (confidence {p:.0%})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("command", choices=["train", "predict"])
    ap.add_argument("log", nargs="?", default="auth.log")
    a = ap.parse_args()
    train() if a.command == "train" else predict(a.log)
