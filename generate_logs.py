"""Generate a reproducible synthetic auth log with labelled attacks.

Scenarios (all attackers are 10.0.0.x, normal users are 192.168.1.x):
  burst     10.0.0.99  50 failures, 1/s
  boundary  10.0.0.77  20 failures, 1/s, split 10+10 across a minute boundary
  slow      10.0.0.55  1 failure every 8 s for 10 minutes ("low and slow")
  clumsy    192.168.1.4 benign user who mistypes a password 4 times (hard negative)
"""
import json
import random
from datetime import datetime, timedelta

def generate(seed=42, path="data/sample.log", labels_path="data/labels.json"):
    rng = random.Random(seed)
    start = datetime(2026, 10, 26, 10, 0, 0)
    users = [f"192.168.1.{i}" for i in range(2, 12)]
    events = []

    for i in range(950):  # normal traffic, ~10% failures
        t = start + timedelta(seconds=i * 3 + rng.randint(0, 2))
        status = rng.choices(["SUCCESS", "FAILED"], weights=[9, 1])[0]
        events.append((t, rng.choice(users), status))

    attacks = {
        "10.0.0.99": (start + timedelta(minutes=20), 50, 1),
        "10.0.0.77": (start + timedelta(minutes=34, seconds=50), 20, 1),
        "10.0.0.55": (start + timedelta(minutes=40), 75, 8),
    }
    for ip, (t0, n, gap) in attacks.items():
        events += [(t0 + timedelta(seconds=i * gap), ip, "FAILED") for i in range(n)]

    t0 = start + timedelta(minutes=12)  # clumsy but legitimate user
    events += [(t0 + timedelta(seconds=i * 5), "192.168.1.4", "FAILED") for i in range(4)]
    events.append((t0 + timedelta(seconds=22), "192.168.1.4", "SUCCESS"))

    events.sort()
    with open(path, "w") as f:
        for t, ip, status in events:
            f.write(f"{t:%Y-%m-%d %H:%M:%S} {ip} LOGIN {status}\n")
    with open(labels_path, "w") as f:
        json.dump({"attackers": sorted(attacks), "benign_noisy": ["192.168.1.4"]}, f)
    return len(events)

if __name__ == "__main__":
    print("Created data/sample.log with", generate(), "lines")
