# log-anomaly

Detecting brute-force login attempts in authentication logs, comparing a fixed rule against statistical and machine-learning anomaly detection.

## Why

A fixed rule such as "more than 10 failed logins in a minute" is easy to evade: an attacker can split attempts across a minute boundary or simply go slowly. This project compares four detectors on the same labelled log to show what each one catches and misses.

## Detectors

| Detector | Type | Idea |
|---|---|---|
| `naive_minute` | Rule | More than 10 failures per IP in a calendar minute |
| `sliding_rule` | Rule | More than 10 failures per IP in any 60-second window |
| `robust_z` | Statistical | Flags windows whose failure count is far above the median (median/MAD z-score) |
| `iforest` | Machine learning | Isolation Forest on per-window features (failures, attempts, failure ratio) |

## Quick start

```
pip install -r requirements.txt
python generate_logs.py
python detector.py data/sample.log --labels data/labels.json
python test_detector.py
```

Use `python3` instead of `python` on Mac/Linux. Without scikit-learn, the first three detectors still run.

## Log format

```
2026-10-26 10:00:01 192.168.1.8 LOGIN FAILED
```

Malformed lines are skipped and counted. To run on your own log, pass its path: `python detector.py your.log`.

## Synthetic data

`generate_logs.py` (seed 42) creates about 1,100 lines: normal traffic from 10 internal users (about 10% failures), three labelled attackers, and one legitimate user who mistypes a password 4 times (a hard negative).

| Attacker | Pattern |
|---|---|
| 10.0.0.99 | 50 failures, 1 per second |
| 10.0.0.77 | 20 failures split 10 + 10 across a minute boundary |
| 10.0.0.55 | 1 failure every 8 seconds for 10 minutes ("low and slow") |

## Results (seed 42)

| Detector | Caught | False alarms | Precision | Recall |
|---|---|---|---|---|
| naive_minute | 1 / 3 | 0 | 1.00 | 0.33 |
| sliding_rule | 2 / 3 | 0 | 1.00 | 0.67 |
| robust_z | 3 / 3 | 0 | 1.00 | 1.00 |
| iforest | 2 / 3 | 0 | 1.00 | 0.67 |

- The per-minute rule misses the boundary-split attack.
- The sliding window fixes that but misses the slow attack, which stays under its fixed threshold.
- The statistical detector catches all three by learning the normal failure rate from the data.
- Isolation Forest is the least stable: it missed the slow attack, and on some other seeds it flagged the legitimate user who mistyped a password. Its `contamination` setting is effectively a guess of how many attacks exist.

## Limitations

- **Synthetic data.** Results on generated logs are optimistic and do not show real-world accuracy. Testing on real or public authentication data is future work.
- **Small sample.** Three attackers and one seed. Results vary by seed, especially for Isolation Forest.
- **Password spraying is not covered.** A few failures from many IPs stays under every per-IP threshold.
- **Thresholds are untuned.** Defaults (10 failures, z = 5, contamination 0.005) were chosen by hand.
- Per-IP detection only; no usernames, geolocation, or time-of-day features.

## Tests

`python test_detector.py` runs 5 unit tests covering parsing, boundary-split attacks, normal-noise false positives, and malformed input.

## License

MIT. Add a `LICENSE` file before publishing.
