import json
from pathlib import Path

DATASET_FILE = Path(__file__).parent / "ta1-theia-e3-official-3.json"

TARGET_COMMANDS = ("sudo ./init.sh", "sh ./init.sh")


def get_command(event):
    properties = event.get("properties", {})
    if isinstance(properties, dict):
        properties = properties.get("map", {})
        if isinstance(properties, dict):
            return properties.get("cmdLine", "")
    return ""


print("Inspecting execution events...")

with DATASET_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        for record_type, event in record.get("datum", {}).items():
            if not record_type.endswith(".Event"):
                continue

            if event.get("type") != "EVENT_EXECUTE":
                continue

            command = get_command(event)

            if any(target in command for target in TARGET_COMMANDS):
                print("\n--- Execution Event ---")
                print("Command:", command)
                print("Timestamp:", event.get("timestampNanos"))
                print("Event UUID:", event.get("uuid"))
                print("Subject:", json.dumps(event.get("subject")))
                print("Predicate Object:", json.dumps(event.get("predicateObject")))
                print("Predicate Object 2:", json.dumps(event.get("predicateObject2")))
                print("Host ID:", event.get("hostId"))
                print("Parent Subject:", json.dumps(event.get("parentSubject")))
                print("Available fields:", list(event.keys()))

print("\nInspection completed.")

