import json
import csv
from pathlib import Path
from collections import Counter

import detect_suspicious
import batch_config


BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = batch_config.DATASET_FILE

OUTPUT_FILE = BASE_DIR / "streaming_detection_results.csv"

BATCH_SIZE = 5000


def extract_event(datum):

    for name, event in datum.items():

        if not name.endswith(".Event"):
            continue

        if not isinstance(event, dict):
            continue

        properties = event.get("properties", {})

        command = ""

        if isinstance(properties, dict):

            property_map = properties.get("map", {})

            if isinstance(property_map, dict):
                command = property_map.get("cmdLine", "")

        return {
            "event_uuid": event.get("uuid", ""),
            "timestamp": event.get("timestampNanos", ""),
            "host_id": event.get("hostId", ""),
            "event_type": event.get("type", ""),
            "command_line": command
        }

    return None


def run_streaming_detection(start_record, end_record):

    print("\nStarting Streaming Rule-Based Detection...")

    if not DATASET_FILE.exists():
        raise FileNotFoundError("DARPA dataset not found.")

    total_events = 0
    execution_events = 0
    flagged_events = 0

    rule_counts = Counter()

    output_columns = [
        "event_uuid",
        "timestamp",
        "host_id",
        "command_line",
        "matched_rules",
        "reasons",
        "risk_score",
        "severity",
        "status"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8-sig"
    ) as output_file:

        writer = csv.DictWriter(
            output_file,
            fieldnames=output_columns
        )

        writer.writeheader()

        with open(
            DATASET_FILE,
            "r",
            encoding="utf-8"
        ) as input_file:

            record_number = 0

            for line in input_file:

                if not line.strip():
                    continue

                record_number += 1

                if record_number < start_record:
                    continue

                if record_number > end_record:
                    break

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                datum = record.get("datum", {})

                if not isinstance(datum, dict):
                    continue

                event_data = extract_event(datum)

                if not event_data:
                    continue

                total_events += 1

                if event_data["event_type"] != "EVENT_EXECUTE":
                    continue

                execution_events += 1

                command = event_data["command_line"]

                matches = detect_suspicious.analyze_command(command)

                if not matches:
                    continue

                flagged_events += 1

                score = min(
                    sum(item["score"] for item in matches),
                    10
                )

                if score >= 8:
                    severity = "HIGH"
                elif score >= 5:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"

                matched_rules = [
                    item["rule"] for item in matches
                ]

                reasons = [
                    item["reason"] for item in matches
                ]

                for rule in matched_rules:
                    rule_counts[rule] += 1

                writer.writerow({

                    "event_uuid": event_data["event_uuid"],
                    "timestamp": event_data["timestamp"],
                    "host_id": event_data["host_id"],
                    "command_line": command,
                    "matched_rules": "; ".join(matched_rules),
                    "reasons": "; ".join(reasons),
                    "risk_score": score,
                    "severity": severity,
                    "status": "REVIEW_REQUIRED"

                })

                if total_events % 10000 == 0:
                    print(
                        f"Records processed: {record_number:,}"
                    )

    print("\n--- Rule Detection Summary ---")

    print("Selected record range:", start_record, "-", end_record)
    print("Events examined:", total_events)
    print("Execution events analysed:", execution_events)
    print("Events requiring review:", flagged_events)

    print("\nRule matches:")

    for rule, count in sorted(rule_counts.items()):
        print(f"{rule}: {count}")

    print("\nResults saved to:", OUTPUT_FILE)


if __name__ == "__main__":

    start, end = batch_config.get_batch_range(1)

    run_streaming_detection(start, end)