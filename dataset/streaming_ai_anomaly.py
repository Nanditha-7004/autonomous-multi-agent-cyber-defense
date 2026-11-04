import json
import csv

import pandas as pd

from pathlib import Path
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest

import batch_config


BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = batch_config.DATASET_FILE

FEATURE_FILE = BASE_DIR / "streaming_ai_features.csv"

OUTPUT_FILE = BASE_DIR / "streaming_ai_anomaly_results.csv"

CONTAMINATION = 0.05

RANDOM_STATE = 42


def extract_event(datum):

    for name, event in datum.items():

        if not name.endswith(".Event"):
            continue

        if not isinstance(event, dict):
            continue

        if event.get("type") != "EVENT_EXECUTE":
            continue

        properties = event.get("properties", {})

        property_map = {}

        if isinstance(properties, dict):
            property_map = properties.get("map", {})

        if not isinstance(property_map, dict):
            property_map = {}

        return {

            "event_uuid": event.get("uuid", ""),

            "timestamp": event.get("timestampNanos", ""),

            "command_line": property_map.get("cmdLine", ""),

            "executable_path": property_map.get("path", ""),

            "parent_process_id": ""

        }

    return None


def extract_features(event):

    command = str(event["command_line"] or "")

    path = str(event["executable_path"] or "")

    try:
        timestamp = float(event["timestamp"])
    except (TypeError, ValueError):
        timestamp = 0.0

    has_parent = (
        1 if str(event["parent_process_id"]).strip() else 0
    )

    return {

        "command_length": len(command),

        "path_length": len(path),

        "has_parent_process": has_parent,

        "timestamp_numeric": timestamp

    }


def extract_dataset_features(start_record, end_record):

    print("\nStarting AI Feature Extraction...")

    if not DATASET_FILE.exists():
        raise FileNotFoundError("DARPA dataset not found.")

    feature_columns = [

        "event_uuid",
        "timestamp",
        "command_line",
        "executable_path",
        "parent_process_id",
        "command_length",
        "path_length",
        "has_parent_process",
        "timestamp_numeric"

    ]

    total_lines = 0
    execution_events = 0

    with open(
        FEATURE_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as output_file:

        writer = csv.DictWriter(
            output_file,
            fieldnames=feature_columns
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

                total_lines += 1

                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                datum = record.get("datum", {})

                if not isinstance(datum, dict):
                    continue

                event = extract_event(datum)

                if event is None:
                    continue

                features = extract_features(event)

                writer.writerow({
                    **event,
                    **features
                })

                execution_events += 1

                if total_lines % 10000 == 0:
                    print(
                        f"Records processed: {total_lines:,}"
                    )

    print("Execution events extracted:", execution_events)

    return execution_events


def train_anomaly_model(features_df):

    feature_columns = [

        "command_length",
        "path_length",
        "has_parent_process",
        "timestamp_numeric"

    ]

    X = features_df[feature_columns].copy()

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(

        n_estimators=100,

        contamination=CONTAMINATION,

        random_state=RANDOM_STATE

    )

    model.fit(X_scaled)

    return model, X_scaled


def run_streaming_ai_detection(start_record, end_record):

    print("\nStarting Streaming AI Anomaly Detection...")

    total_events = extract_dataset_features(
        start_record,
        end_record
    )

    if total_events < 2:
        raise ValueError(
            "At least two execution events are required."
        )

    features_df = pd.read_csv(
        FEATURE_FILE,
        low_memory=False
    )

    model, X_scaled = train_anomaly_model(features_df)

    print("\nIsolation Forest training completed.")

    predictions = model.predict(X_scaled)

    anomaly_scores = model.decision_function(X_scaled)

    features_df["ai_prediction"] = predictions

    features_df["prediction_label"] = [
        "ANOMALY" if value == -1 else "NORMAL"
        for value in predictions
    ]

    features_df["ai_anomaly_score"] = anomaly_scores

    features_df.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    anomalies = int((predictions == -1).sum())

    normal = int((predictions == 1).sum())

    print("\n--- AI Anomaly Detection Summary ---")

    print("Execution events:", len(features_df))

    print("Anomalies detected:", anomalies)

    print("Normal events:", normal)

    print(
        "Anomaly percentage:",
        round(anomalies / len(features_df) * 100, 2),
        "%"
    )

    print("\nResults saved to:", OUTPUT_FILE)

    print(
        "\nNOTE: An anomaly indicates unusual behaviour. "
        "It does not confirm an attack."
    )


if __name__ == "__main__":

    start, end = batch_config.get_batch_range(1)

    run_streaming_ai_detection(start, end)