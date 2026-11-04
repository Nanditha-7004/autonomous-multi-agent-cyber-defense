import json
import csv
import pandas as pd

from pathlib import Path
from collections import Counter, defaultdict

import batch_config


BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = batch_config.DATASET_FILE

DETECTION_FILE = BASE_DIR / "streaming_detection_results.csv"

ANOMALY_FILE = BASE_DIR / "streaming_ai_anomaly_results.csv"

OUTPUT_FILE = BASE_DIR / "streaming_provenance_results.csv"

MAX_RELATED_EVENTS = 200

TIME_WINDOW_NS = 5 * 60 * 1_000_000_000


def get_uuid(value):

    if isinstance(value, dict):

        return value.get(
            "com.bbn.tc.schema.avro.cdm18.UUID",
            ""
        )

    return ""


def load_suspicious_event_ids():

    suspicious_ids = set()

    if DETECTION_FILE.exists():

        detection_df = pd.read_csv(
            DETECTION_FILE,
            dtype=str
        ).fillna("")

        for _, row in detection_df.iterrows():

            event_id = str(
                row.get("event_uuid", "")
            ).strip()

            if event_id and row.get("status") == "REVIEW_REQUIRED":
                suspicious_ids.add(event_id)

    if ANOMALY_FILE.exists():

        anomaly_df = pd.read_csv(
            ANOMALY_FILE,
            dtype=str
        ).fillna("")

        for _, row in anomaly_df.iterrows():

            prediction = str(
                row.get("ai_prediction", "")
            ).strip()

            label = str(
                row.get("prediction_label", "")
            ).strip().upper()

            if prediction == "-1" or label == "ANOMALY":

                event_id = str(
                    row.get("event_uuid", "")
                ).strip()

                if event_id:
                    suspicious_ids.add(event_id)

    return suspicious_ids


def extract_events(datum):

    events = []

    for name, event in datum.items():

        if not name.endswith(".Event"):
            continue

        if not isinstance(event, dict):
            continue

        events.append({

            "event_uuid": str(event.get("uuid", "")),

            "timestamp": str(event.get("timestampNanos", "")),

            "event_type": str(event.get("type", "")),

            "host_id": str(event.get("hostId", "")),

            "subject_id": get_uuid(event.get("subject")),

            "object_id": get_uuid(event.get("predicateObject")),

            "object2_id": get_uuid(event.get("predicateObject2"))

        })

    return events


def first_pass(suspicious_ids, start_record, end_record):

    print("\nPASS 1: Identifying suspicious events...")

    target_events = {}

    related_entities = defaultdict(set)

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

            for event in extract_events(datum):

                event_id = event["event_uuid"]

                if event_id not in suspicious_ids:
                    continue

                target_events[event_id] = event

                for field in [
                    "subject_id",
                    "object_id",
                    "object2_id"
                ]:

                    entity_id = event[field]

                    if entity_id:
                        related_entities[entity_id].add(event_id)

    print("Suspicious events found:", len(target_events))

    print("Unique related entities:", len(related_entities))

    return target_events, related_entities


def second_pass(target_events, related_entities, start_record, end_record):

    print("\nPASS 2: Investigating related activities...")

    if not target_events:
        print("No suspicious events found.")
        return 0, Counter()

    selected_events = {
        target_id: []
        for target_id in target_events
    }

    target_times = {}

    for target_id, target in target_events.items():

        try:
            target_times[target_id] = int(target["timestamp"])
        except (ValueError, TypeError):
            target_times[target_id] = None

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

            for event in extract_events(datum):

                event_id = event["event_uuid"]

                if not event_id:
                    continue

                event_entities = {
                    event["subject_id"],
                    event["object_id"],
                    event["object2_id"]
                }

                event_entities.discard("")

                matched_targets = set()

                if event_id in target_events:
                    matched_targets.add(event_id)

                for entity_id in event_entities:

                    matched_targets.update(
                        related_entities.get(entity_id, set())
                    )

                for target_id in matched_targets:

                    target = target_events[target_id]

                    if event_id == target_id:
                        distance = 0

                    else:

                        if (
                            not event["host_id"]
                            or event["host_id"] != target["host_id"]
                        ):
                            continue

                        try:
                            event_time = int(event["timestamp"])
                        except (ValueError, TypeError):
                            continue

                        target_time = target_times[target_id]

                        if target_time is None:
                            continue

                        distance = abs(event_time - target_time)

                        if distance > TIME_WINDOW_NS:
                            continue

                    candidates = selected_events[target_id]

                    if len(candidates) < MAX_RELATED_EVENTS:

                        candidates.append((distance, event))

                    else:

                        farthest_index = max(
                            range(len(candidates)),
                            key=lambda i: candidates[i][0]
                        )

                        if distance < candidates[farthest_index][0]:

                            candidates[farthest_index] = (
                                distance,
                                event
                            )

    output_columns = [

        "target_event_uuid",
        "target_event_type",
        "target_timestamp",
        "related_event_uuid",
        "related_event_type",
        "related_timestamp",
        "host_id",
        "subject_id",
        "object_id",
        "object2_id",
        "relationship_type"

    ]

    related_count = 0

    event_type_counts = Counter()

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

        for target_id, candidates in selected_events.items():

            target = target_events[target_id]

            unique_events = {}

            for distance, event in candidates:
                unique_events[event["event_uuid"]] = (
                    distance,
                    event
                )

            sorted_events = sorted(
                unique_events.values(),
                key=lambda item: item[0]
            )

            for distance, event in sorted_events:

                relationship_types = []

                if (
                    event["subject_id"]
                    and target_id in related_entities.get(
                        event["subject_id"], set()
                    )
                ):
                    relationship_types.append("SUBJECT_RELATIONSHIP")

                if (
                    event["object_id"]
                    and target_id in related_entities.get(
                        event["object_id"], set()
                    )
                ):
                    relationship_types.append("OBJECT_RELATIONSHIP")

                if (
                    event["object2_id"]
                    and target_id in related_entities.get(
                        event["object2_id"], set()
                    )
                ):
                    relationship_types.append(
                        "SECOND_OBJECT_RELATIONSHIP"
                    )

                if event["event_uuid"] == target_id:
                    relationship = "TARGET_EVENT"
                else:
                    relationship = "; ".join(relationship_types)

                writer.writerow({

                    "target_event_uuid": target_id,

                    "target_event_type": target["event_type"],

                    "target_timestamp": target["timestamp"],

                    "related_event_uuid": event["event_uuid"],

                    "related_event_type": event["event_type"],

                    "related_timestamp": event["timestamp"],

                    "host_id": event["host_id"],

                    "subject_id": event["subject_id"],

                    "object_id": event["object_id"],

                    "object2_id": event["object2_id"],

                    "relationship_type": relationship

                })

                related_count += 1

                event_type_counts[event["event_type"]] += 1

    print("Related event associations:", related_count)

    return related_count, event_type_counts


def run_streaming_provenance(start_record, end_record):

    print("\nStarting Dynamic Provenance Investigation...")

    if not DATASET_FILE.exists():
        raise FileNotFoundError("DARPA dataset not found.")

    suspicious_ids = load_suspicious_event_ids()

    print("Suspicious event IDs received:", len(suspicious_ids))

    if not suspicious_ids:
        print("No suspicious event IDs available.")
        return

    target_events, related_entities = first_pass(
        suspicious_ids,
        start_record,
        end_record
    )

    if not target_events:
        print("No matching events found in selected batch.")
        return

    related_count, event_type_counts = second_pass(
        target_events,
        related_entities,
        start_record,
        end_record
    )

    print("\n--- Provenance Investigation Summary ---")

    print("Target events found:", len(target_events))

    print("Unique related entities:", len(related_entities))

    print("Related event associations:", related_count)

    print("\nRelated event types:")

    for event_type, count in event_type_counts.most_common():
        print(f"{event_type}: {count}")

    print("\nResults saved to:", OUTPUT_FILE)


if __name__ == "__main__":

    start, end = batch_config.get_batch_range(1)

    run_streaming_provenance(start, end)