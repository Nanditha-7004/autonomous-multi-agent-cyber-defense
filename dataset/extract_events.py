import json
import csv

input_file = "dataset/ta1-theia-e3-official-3.json"
output_file = "execution_events.csv"

count = 0


def get_entity_id(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.endswith(".UUID"):
                return item
    return ""


def get_command_line(details):
    properties = details.get("properties")

    if isinstance(properties, dict):
        command_map = properties.get("map")

        if isinstance(command_map, dict):
            return command_map.get("cmdLine") or ""

    return ""


print("Extracting real execution events from DARPA dataset...")

with open(input_file, "r", encoding="utf-8") as source, \
     open(output_file, "w", newline="", encoding="utf-8") as output:

    columns = [
        "event_uuid",
        "timestamp",
        "host_id",
        "event_type",
        "subject_id",
        "object_id",
        "command_line",
        "executable_path",
        "parent_process_id"
    ]

    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()

    for line in source:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        datum = record.get("datum", {})

        if not isinstance(datum, dict):
            continue

        for details in datum.values():
            if not isinstance(details, dict):
                continue

            if details.get("type") != "EVENT_EXECUTE":
                continue

            writer.writerow({
                "event_uuid": details.get("uuid", ""),
                "timestamp": details.get("timestampNanos", ""),
                "host_id": details.get("hostId", ""),
                "event_type": details.get("type", ""),
                "subject_id": get_entity_id(
                    details.get("subject")
                ),
                "object_id": get_entity_id(
                    details.get("predicateObject")
                ),
                "command_line": get_command_line(details),
                "executable_path": (
                    details.get("predicateObjectPath") or ""
                ),
                "parent_process_id": ""
            })

            count += 1

print("\nExtraction complete!")
print("Execution events extracted:", count)
print("Output file:", output_file)
print("Original JSON dataset was not modified.")
