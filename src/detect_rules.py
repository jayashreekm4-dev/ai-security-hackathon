from collections import Counter

failed = Counter()

with open("data/sample.log") as f:
    for line in f:
        parts = line.split()
        date, time, ip, status = parts[0], parts[1], parts[2], parts[4]
        if status == "FAILED":
            minute = time[:5]
            failed[(ip, date, minute)] += 1

found = False
for (ip, date, minute), count in failed.items():
    if count > 10:
        print("WARNING:", ip, "had", count, "failed logins at", date, minute)
        found = True

if not found:
    print("No attacks found")