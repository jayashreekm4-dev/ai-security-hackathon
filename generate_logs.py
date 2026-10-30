"""Generate reproducible synthetic auth logs with labelled attacks.

Default scenario (seed 42), all attackers are 10.0.0.x, normal users are 192.168.1.x:
  burst     10.0.0.99  50 failures, 1/s
  boundary  10.0.0.77  20 failures, 1/s, split 10+10 across a minute boundary
  slow      10.0.0.55  1 failure every 8 s for 10 minutes ("low and slow")
  clumsy    192.168.1.4 benign user who mistypes a password 4 times (hard negative)

randomize=True varies attack types, timing, size and speed per seed. It is used
to train and test the ML model on many different logs.
"""
import json
import os
import random
from datetime import datetime, timedelta


def make_events(seed=42, randomize=False):
    """Return (sorted [(datetime, ip, status)], set of attacker IPs)."""
    rng = random.Random(seed)
    start = datetime(2026, 10, 26, 10, 0, 0)
    users = [f"192.168.1.{i}" for i in range(2, 12)]
    events = []
    weights = [9, 1]
    if randomize:
        weights = [rng.randint(7, 12), 1]  # normal failure rate roughly 8-12%

    for i in range(950):  # normal traffic
        t = start + timedelta(seconds=i * 3 + rng.randint(0, 2))
        status = rng.choices(["SUCCESS", "FAILED"], weights=weights)[0]
        events.append((t, rng.choice(users), status))

    if not randomize:
        attacks = {
            "10.0.0.99": (start + timedelta(minutes=20), 50, 1),
            "10.0.0.77": (start + timedelta(minutes=34, seconds=50), 20, 1),
            "10.0.0.55": (start + timedelta(minutes=40), 75, 8),
        }
        clumsy_ip, clumsy_n, clumsy_t = "192.168.1.4", 4, start + timedelta(minutes=12)
    else:
        attacks = {}
        kinds = rng.sample(["burst", "boundary", "slow"], rng.randint(1, 3))
        for kind, last in zip(kinds, rng.sample(range(10, 250), len(kinds))):
            if kind == "burst":
                n, gap = rng.randint(30, 80), 1
                t0 = start + timedelta(seconds=rng.randint(60, 2400))
            elif kind == "boundary":
                n, gap = rng.randint(16, 30), 1
                t0 = start + timedelta(minutes=rng.randint(2, 40), seconds=-(n // 2))
            else:
                n, gap = rng.randint(50, 90), rng.randint(6, 9)
                t0 = start + timedelta(seconds=rng.randint(60, 1800))
            attacks[f"10.0.0.{last}"] = (t0, n, gap)
        clumsy_ip, clumsy_n = rng.choice(users), rng.randint(3, 5)
        clumsy_t = start + timedelta(seconds=rng.randint(60, 2400))

    for ip, (t0, n, gap) in attacks.items():
        events += [(t0 + timedelta(seconds=i * gap), ip, "FAILED") for i in range(n)]
    events += [(clumsy_t + timedelta(seconds=i * 5), clumsy_ip, "FAILED") for i in range(clumsy_n)]
    events.append((clumsy_t + timedelta(seconds=clumsy_n * 5 + 2), clumsy_ip, "SUCCESS"))

    events.sort()
    return events, set(attacks)


def generate(seed=42, path="data/sample.log", labels_path="data/labels.json", randomize=False):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    events, attackers = make_events(seed, randomize)
    with open(path, "w") as f:
        for t, ip, status in events:
            f.write(f"{t:%Y-%m-%d %H:%M:%S} {ip} LOGIN {status}\n")
    with open(labels_path, "w") as f:
        json.dump({"attackers": sorted(attackers)}, f)
    return len(events)


if __name__ == "__main__":
    print("Created data/sample.log with", generate(), "lines")
