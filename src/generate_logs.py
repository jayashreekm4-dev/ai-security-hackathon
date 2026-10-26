import random
from datetime import datetime, timedelta

start = datetime(2026, 10, 26, 10, 0, 0)
normal_ips = ["192.168.1." + str(i) for i in range(2, 12)]
attacker_ip = "10.0.0.99"
lines = []

# normal activity
for i in range(950):
    time = start + timedelta(seconds=i * 3 + random.randint(0, 2))
    ip = random.choice(normal_ips)
    status = random.choices(["SUCCESS", "FAILED"], weights=[9, 1])[0]
    lines.append((time, ip, status))

# attack: 50 failed logins in one minute
attack_start = start + timedelta(minutes=20)
for i in range(50):
    time = attack_start + timedelta(seconds=i)
    lines.append((time, attacker_ip, "FAILED"))

lines.sort()
with open("data/sample.log", "w") as f:
    for time, ip, status in lines:
        f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} {ip} LOGIN {status}\n")

print("Done! Created data/sample.log with", len(lines), "lines")