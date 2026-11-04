import csv
from collections import Counter

filename = "execution_events.csv"
total = 0
hosts = Counter()
timestamps = []
event_types = Counter()

print("Analyzing real DARPA execution events...")

with open(filename, "r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total += 1
        hosts[row.get("host_id", "UNKNOWN")] += 1
        event_types[row.get("event_type", "UNKNOWN")] += 1

        try:
            timestamps.append(int(row["timestamp"]))
        except (ValueError, TypeError, KeyError):
            pass

print("\n--- Execution Event Analysis ---")
print("Total records:", total)
print("Unique hosts:", len(hosts))
print("Event types:", dict(event_types))
print("Valid timestamps:", len(timestamps))