import json
from pathlib import Path
from collections import Counter

DATASET_FILE = Path(__file__).parent / "ta1-theia-e3-official-3.json"

print("Analysing DARPA cybersecurity data...")
print("Dataset:", DATASET_FILE)

event_counts = Counter()
record_counts = Counter()
invalid_lines = 0

with DATASET_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue

        datum = record.get("datum", {})

        for record_name, event in datum.items():
            record_counts[record_name] += 1

            if record_name.endswith(".Event"):
                event_counts[event.get("type", "UNKNOWN")] += 1

print("\n--- Dataset Analysis Summary ---")
print("Total records:", sum(record_counts.values()))
print("Invalid JSON lines:", invalid_lines)

print("\n--- Record Types ---")
for name, count in record_counts.most_common():
    print(f"{name}: {count}")

print("\n--- Event Type Counts ---")
for name, count in event_counts.most_common():
    print(f"{name}: {count}")

print("\nDataset analysis completed.")

