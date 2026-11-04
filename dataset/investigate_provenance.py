import json
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = BASE_DIR / "ta1-theia-e3-official-3.json"

OUTPUT_FILE = BASE_DIR / "provenance_investigation.csv"

TARGET_COMMANDS = (
    "sudo ./init.sh",
    "sh ./init.sh"
)

MAX_DISPLAY = 10


# --------------------------------------------------
# FUNCTION 1: EXTRACT DARPA UUID
# --------------------------------------------------

def get_uuid(value):

    if isinstance(value, dict):

        return value.get(
            "com.bbn.tc.schema.avro.cdm18.UUID"
        )

    return None


# --------------------------------------------------
# FUNCTION 2: EXTRACT DARPA COMMAND
# --------------------------------------------------

def get_command(event):

    properties = event.get("properties", {})

    if isinstance(properties, dict):

        properties = properties.get("map", {})

        if isinstance(properties, dict):

            return properties.get("cmdLine", "")

    return ""


# --------------------------------------------------
# FUNCTION 3: CHECK VALID UUID
# --------------------------------------------------

def is_valid_uuid(value):

    return (
        isinstance(value, str)
        and bool(value.strip())
        and set(value.replace("-", "")) != {"0"}
    )


# --------------------------------------------------
# FUNCTION 4: LOAD DARPA JSONL DATASET
# --------------------------------------------------

def load_darpa_dataset(file_path):

    records = []

    with open(file_path, "r", encoding="utf-8") as file:

        for line in file:

            try:

                record = json.loads(line)

            except json.JSONDecodeError:

                continue

            datum = record.get("datum", {})

            if not isinstance(datum, dict):
                continue

            for record_name, event in datum.items():

                if not record_name.endswith(".Event"):
                    continue

                records.append({

                    "event_uuid": event.get("uuid", ""),

                    "timestamp": event.get(
                        "timestampNanos", ""
                    ),

                    "event_type": event.get("type", ""),

                    "host_id": event.get("hostId", ""),

                    "subject_id": get_uuid(
                        event.get("subject")
                    ) or "",

                    "object_id": get_uuid(
                        event.get("predicateObject")
                    ) or "",

                    "object2_id": get_uuid(
                        event.get("predicateObject2")
                    ) or "",

                    "command_line": get_command(event)

                })

    return pd.DataFrame(records)


# --------------------------------------------------
# FUNCTION 5: RUN PROVENANCE INVESTIGATION
# --------------------------------------------------

def run_provenance_investigation(
    df,
    detections_df=None,
    target_commands=TARGET_COMMANDS
):

    if df.empty:

        raise ValueError(
            "Dataset is empty. Provenance investigation cannot run."
        )

    df = df.copy()

    # Required columns
    required_columns = [
        "event_uuid",
        "timestamp",
        "event_type",
        "host_id",
        "subject_id",
        "object_id",
        "object2_id",
        "command_line"
    ]

    for column in required_columns:

        if column not in df.columns:

            df[column] = ""

    # Convert missing values into empty strings
    for column in required_columns:

        df[column] = (
            df[column]
            .fillna("")
            .astype(str)
            .str.strip()
        )

    # --------------------------------------------------
    # STEP 1: IDENTIFY TARGET EVENTS
    # --------------------------------------------------

    target_events = pd.DataFrame()

    # Use detection results when provided
    if detections_df is not None and not detections_df.empty:

        if "event_uuid" in detections_df.columns:

            detected_ids = set(
                detections_df["event_uuid"]
                .dropna()
                .astype(str)
                .str.strip()
            )

            detected_ids.discard("")

            target_events = df[
                df["event_uuid"].isin(detected_ids)
            ].copy()

    # Fallback: identify target commands
    if target_events.empty:

        target_events = df[
            df["command_line"].apply(
                lambda command: any(
                    target.lower() in command.lower()
                    for target in target_commands
                )
            )
        ].copy()

    if target_events.empty:

        return pd.DataFrame(columns=[
            "target_event_uuid",
            "target_command",
            "timestamp",
            "event_type",
            "host_id",
            "subject_id",
            "object_id",
            "command_line",
            "event_uuid"
        ])

    # --------------------------------------------------
    # STEP 2: IDENTIFY TARGET SUBJECTS
    # --------------------------------------------------

    target_subjects = set()

    for _, target in target_events.iterrows():

        subject_id = target["subject_id"]

        if is_valid_uuid(subject_id):

            target_subjects.add(subject_id)

    # --------------------------------------------------
    # STEP 3: FIND RELATED EVENTS
    # --------------------------------------------------

    results = []

    seen_events = set()

    for _, target in target_events.iterrows():

        target_event_id = target["event_uuid"]

        target_subject = target["subject_id"]

        if not is_valid_uuid(target_subject):

            continue

        for _, event in df.iterrows():

            connected_ids = {

                event["subject_id"],

                event["object_id"],

                event["object2_id"]

            }

            connected_ids = {

                value
                for value in connected_ids
                if is_valid_uuid(value)

            }

            if target_subject not in connected_ids:

                continue

            event_id = event["event_uuid"]

            unique_key = (

                target_event_id,

                event_id if event_id else (
                    event["timestamp"],
                    event["event_type"],
                    event["subject_id"],
                    event["object_id"]
                )

            )

            if unique_key in seen_events:

                continue

            seen_events.add(unique_key)

            results.append({

                "target_event_uuid": target_event_id,

                "target_command": target["command_line"],

                "timestamp": event["timestamp"],

                "event_type": event["event_type"],

                "host_id": event["host_id"],

                "subject_id": event["subject_id"],

                "object_id": event["object_id"],

                "command_line": event["command_line"],

                "event_uuid": event_id

            })

    return pd.DataFrame(results)


# --------------------------------------------------
# FUNCTION 6: INDEPENDENT SCRIPT EXECUTION
# --------------------------------------------------

def main():

    print("\nStarting Provenance Investigation Agent...")

    print("Dataset:", DATASET_FILE)

    if not DATASET_FILE.exists():

        print("ERROR: DARPA dataset not found.")

        return

    # Load original DARPA dataset
    df = load_darpa_dataset(DATASET_FILE)

    print("Total events loaded:", len(df))

    try:

        results = run_provenance_investigation(df)

    except ValueError as error:

        print("ERROR:", error)

        return

    # Save investigation results
    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # Calculate summary
    target_count = results[
        "target_event_uuid"
    ].nunique() if not results.empty else 0

    related_count = len(results)

    unique_subjects = results[
        "subject_id"
    ].nunique() if not results.empty else 0

    print("\n--- Provenance Investigation Summary ---")

    print(
        "Target execution events:",
        target_count
    )

    print(
        "Related event associations:",
        related_count
    )

    print(
        "Unique related subjects:",
        unique_subjects
    )

    print(
        "\nResults saved to:",
        OUTPUT_FILE
    )

    print("\n--- Related Events ---")

    if not results.empty:

        for _, row in results.head(MAX_DISPLAY).iterrows():

            print(
                row["target_command"],
                "|",
                row["event_type"],
                "|",
                row["command_line"] or "(no command)"
            )

    else:

        print("No related events found.")

    print("\nInvestigation completed.")

    print(
        "NOTE: Related events provide investigation context. "
        "They are not automatically malicious."
    )


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

if __name__ == "__main__":

    main()