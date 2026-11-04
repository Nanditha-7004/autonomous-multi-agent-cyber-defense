import pandas as pd
import numpy as np
from pathlib import Path

from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "execution_events.csv"
OUTPUT_FILE = BASE_DIR / "ai_anomaly_results.csv"


# --------------------------------------------------
# FUNCTION 1: PREPARE FEATURES
# --------------------------------------------------

def prepare_features(df):

    df = df.copy()

    required_columns = [
        "command_line",
        "executable_path",
        "parent_process_id",
        "timestamp"
    ]

    # Add missing columns
    for column in required_columns:

        if column not in df.columns:
            df[column] = pd.NA

    # Feature 1: Command length
    df["command_length"] = (
        df["command_line"]
        .astype("string")
        .fillna("")
        .str.len()
    )

    # Feature 2: Executable path length
    df["path_length"] = (
        df["executable_path"]
        .astype("string")
        .fillna("")
        .str.len()
    )

    # Feature 3: Check whether parent process exists
    parent_values = (
        df["parent_process_id"]
        .astype("string")
        .fillna("")
        .str.strip()
    )

    df["has_parent_process"] = (
        parent_values != ""
    ).astype(int)

    # Feature 4: Convert timestamp into numeric values
    numeric_timestamp = pd.to_numeric(
        df["timestamp"],
        errors="coerce"
    )

    datetime_timestamp = pd.to_datetime(
        df["timestamp"],
        errors="coerce",
        utc=True
    )

    datetime_numeric = (
        datetime_timestamp.astype("int64") / 10**9
    )

    datetime_numeric = datetime_numeric.where(
        datetime_timestamp.notna(),
        np.nan
    )

    df["timestamp_numeric"] = numeric_timestamp.fillna(
        datetime_numeric
    )

    # Replace missing timestamp values
    df["timestamp_numeric"] = (
        df["timestamp_numeric"].fillna(0)
    )

    # Select four features
    features = df[
        [
            "command_length",
            "path_length",
            "has_parent_process",
            "timestamp_numeric"
        ]
    ].astype(float)

    return df, features


# --------------------------------------------------
# FUNCTION 2: RUN AI ANOMALY DETECTION
# --------------------------------------------------

def run_anomaly_detection(df):

    if df.empty:

        raise ValueError(
            "Uploaded dataset is empty."
        )

    useful_columns = [
        "command_line",
        "executable_path",
        "parent_process_id",
        "timestamp"
    ]

    available_columns = [
        column
        for column in useful_columns
        if column in df.columns
    ]

    if not available_columns:

        raise ValueError(
            "AI anomaly detection requires at least one "
            "of these columns: command_line, executable_path, "
            "parent_process_id or timestamp."
        )

    # Prepare features
    processed_df, features = prepare_features(df)

    # Standardize features
    scaler = StandardScaler()

    scaled_features = scaler.fit_transform(features)

    # Create Isolation Forest model
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )

    # Train model and predict anomalies
    predictions = model.fit_predict(
        scaled_features
    )

    # Store predictions
    processed_df["ai_prediction"] = predictions

    processed_df["ai_anomaly_status"] = np.where(
        predictions == -1,
        "ANOMALY",
        "NORMAL"
    )

    # Calculate anomaly scores
    processed_df["ai_anomaly_score"] = (
        model.decision_function(scaled_features)
    )

    return processed_df


# --------------------------------------------------
# FUNCTION 3: INDEPENDENT SCRIPT EXECUTION
# --------------------------------------------------

def main():

    if not INPUT_FILE.exists():

        print(
            "ERROR: Input file not found:",
            INPUT_FILE
        )

        return

    df = pd.read_csv(INPUT_FILE)

    try:

        results = run_anomaly_detection(df)

    except ValueError as error:

        print("ERROR:", error)

        return

    # Save results
    results.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # Separate anomalies and normal events
    anomalies = results[
        results["ai_prediction"] == -1
    ]

    normal = results[
        results["ai_prediction"] == 1
    ]

    # Display summary
    print("\n--- AI Anomaly Detection Summary ---")

    print(
        "Total events analysed:",
        len(results)
    )

    print(
        "Anomalies detected:",
        len(anomalies)
    )

    print(
        "Normal events:",
        len(normal)
    )

    print(
        "\nResults saved to:",
        OUTPUT_FILE
    )

    print(
        "\nIMPORTANT: An anomaly indicates unusual behaviour "
        "according to the model. It does not confirm an attack."
    )


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

if __name__ == "__main__":

    main()