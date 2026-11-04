import csv
from pathlib import Path

DATASET_DIR = Path(__file__).parent

INPUT_FILE = DATASET_DIR / "provenance_investigation.csv"
OUTPUT_FILE = DATASET_DIR / "process_relationship_report.csv"

EVENT_NOTES = {
    "EVENT_CLONE": "Process-related activity; examine process relationships",
    "EVENT_OPEN": "Resource opened; examine the associated file or object",
    "EVENT_MMAP": "Memory mapping activity; examine execution context",
    "EVENT_EXECUTE": "Program execution; review the command",
    "EVENT_READ": "Read activity; examine the accessed resource",
    "EVENT_MPROTECT": "Memory protection change; investigate context",
    "EVENT_CONNECT": "Network connection activity; examine destination",
    "EVENT_RECVFROM": "Network receive activity; examine communication",
    "EVENT_SENDTO": "Network send activity; examine communication",
    "EVENT_WRITE": "Write activity; examine the modified resource",
}

print("Preparing investigation timeline...")

with INPUT_FILE.open("r", newline="", encoding="utf-8") as file:
    events = list(csv.DictReader(file))

events.sort(key=lambda event: int(event.get("timestamp") or 0))

columns = [
    "timestamp",
    "event_type",
    "subject_id",
    "object_id",
    "command_line",
    "investigation_note",
]

with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
    writer = csv.DictWriter(file, fieldnames=columns)
    writer.writeheader()

    for event in events:
        event_type = event.get("event_type", "")
        command = event.get("command_line", "")

        note = EVENT_NOTES.get(
            event_type,
            "Review event details and related activity"
        )

        if event_type == "EVENT_EXECUTE":
            note = "Execution event; review command and surrounding activity"

            if command in ("sudo ./init.sh", "sh ./init.sh"):
                note += "; identified command requires investigation"

        writer.writerow({
            "timestamp": event.get("timestamp", ""),
            "event_type": event_type,
            "subject_id": event.get("subject_id", ""),
            "object_id": event.get("object_id", ""),
            "command_line": command,
            "investigation_note": note,
        })

print("Related events processed:", len(events))
print("Execution events:", sum(
    event.get("event_type") == "EVENT_EXECUTE"
    for event in events
))
print("Report saved to:", OUTPUT_FILE)
print("Timeline analysis completed.")

