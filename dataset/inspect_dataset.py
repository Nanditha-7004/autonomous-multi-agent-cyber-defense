
import json
from collections import Counter

filename = "dataset/ta1-theia-e3-official-3.json"
counts = Counter()
total = 0
invalid = 0

print("Inspecting DARPA dataset...")

with open(filename, "r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
            datum = record.get("datum", {})

            if isinstance(datum, dict):
                counts.update(datum.keys())
                total += 1
            else:
                invalid += 1
        except (json.JSONDecodeError, AttributeError):
            invalid += 1

print("\nInspection complete!")
print("Valid records:", total)
print("Invalid records:", invalid)
print("\nRecord types:")

for name, count in counts.most_common():
    print(f"{name}: {count}")