import json
from pathlib import Path
from collections import Counter, defaultdict

DATASET_FILE = (
    Path(__file__).resolve().parent
    / "ta1-theia-e3-official-3.json"
)

event_type_counts = Counter()
field_counts = defaultdict(Counter)
sample_events = {}
total_records = 0
invalid_lines = 0

print("Analyzing DARPA dataset event structure...")
print("Dataset:", DATASET_FILE)

with DATASET_FILE.open("r", encoding="utf-8") as file:
    for line_number, line in enumerate(file, start=1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            invalid_lines += 1
            continue

        total_records += 1
        datum = record.get("datum", {})

        if not isinstance(datum, dict):
            continue

        for record_type, details in datum.items():
            if not record_type.endswith(".Event"):
                continue

            if not isinstance(details, dict):
                continue

            event_type = details.get("type", "UNKNOWN")
            event_type_counts[event_type] += 1

            # Count fields available for each event type.
            for field in details:
                field_counts[event_type][field] += 1

            # Retain one representative event of each type.
            if event_type not in sample_events:
                sample_events[event_type] = details

print("\n========== DATASET SUMMARY ==========")
print("Records processed:", total_records)
print("Invalid JSON lines:", invalid_lines)
print("Distinct event types:", len(event_type_counts))

print("\n========== EVENT TYPE COUNTS ==========")

for event_type, count in event_type_counts.most_common():
    print(f"{event_type}: {count:,}")

print("\n========== EVENT FIELD AVAILABILITY ==========")

for event_type in sorted(sample_events):
    print(f"\nEvent type: {event_type}")
    print("Fields:", ", ".join(sorted(field_counts[event_type])))

print("\n========== SAMPLE EVENT STRUCTURE ==========")

for event_type in [
    "EVENT_EXECUTE",
    "EVENT_OPEN",
    "EVENT_READ",
    "EVENT_WRITE",
    "EVENT_CONNECT",
    "EVENT_RECVFROM",
    "EVENT_MMAP",
    "EVENT_MPROTECT",
]:
    if event_type in sample_events:
        print(f"\n--- {event_type} ---")
        print(json.dumps(sample_events[event_type], indent=2)[:2500])

print("\nAnalysis complete.")

