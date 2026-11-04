import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

DETECTION_FILE = BASE_DIR / "streaming_detection_results.csv"

ANOMALY_FILE = BASE_DIR / "streaming_ai_anomaly_results.csv"

PROVENANCE_FILE = BASE_DIR / "streaming_provenance_results.csv"

OUTPUT_FILE = BASE_DIR / "streaming_risk_assessment_results.csv"


HIGH_RISK_RULES = {
    "DESTRUCTIVE_COMMAND",
    "PERSISTENCE_INDICATOR",
    "PROCESS_INJECTION",
    "MEMORY_INJECTION"
}

MEDIUM_RISK_RULES = {
    "PRIVILEGED_COMMAND",
    "CREDENTIAL_ACCESS",
    "SUSPICIOUS_NETWORK"
}

LOW_RISK_RULES = {
    "SHELL_EXECUTION",
    "DOWNLOAD_AND_EXECUTE",
    "NETWORK_UTILITY"
}


def load_file(path):

    if not path.exists():
        print("WARNING: File not found:", path.name)
        return pd.DataFrame()

    return pd.read_csv(
        path,
        dtype=str
    ).fillna("")


def normalize_id(value):

    if pd.isna(value):
        return ""

    return str(value).strip()


def calculate_rule_risk(matched_rules):

    rules = {
        rule.strip().upper()
        for rule in str(matched_rules).split(";")
        if rule.strip()
    }

    if rules & HIGH_RISK_RULES:
        return 80

    if rules & MEDIUM_RISK_RULES:
        return 60

    if rules & LOW_RISK_RULES:
        return 40

    if rules:
        return 20

    return 0


def recommend_action(risk_level):

    if risk_level == "HIGH":
        return "URGENT_ANALYST_REVIEW"

    elif risk_level == "MEDIUM":
        return "INVESTIGATE"

    return "MONITOR"


def run_risk_assessment(start_record, end_record):

    print("\nStarting Streaming Risk Assessment Agent...")

    detection_df = load_file(DETECTION_FILE)

    anomaly_df = load_file(ANOMALY_FILE)

    provenance_df = load_file(PROVENANCE_FILE)

    print("\n--- Input Summary ---")

    print("Rule detection records:", len(detection_df))

    print("AI anomaly records:", len(anomaly_df))

    print("Provenance associations:", len(provenance_df))

    # Prepare rule detections

    rule_records = {}

    if not detection_df.empty:

        for _, row in detection_df.iterrows():

            event_id = normalize_id(
                row.get("event_uuid", "")
            )

            if not event_id:
                continue

            rule_records[event_id] = {

                "matched_rules": row.get("matched_rules", ""),

                "command_line": row.get("command_line", ""),

                "timestamp": row.get("timestamp", ""),

                "host_id": row.get("host_id", "")

            }

    # Prepare AI anomalies

    anomaly_records = {}

    if not anomaly_df.empty:

        for _, row in anomaly_df.iterrows():

            prediction = str(
                row.get("ai_prediction", "")
            ).strip()

            label = str(
                row.get("prediction_label", "")
            ).strip().upper()

            is_anomaly = (
                prediction == "-1"
                or label == "ANOMALY"
            )

            if not is_anomaly:
                continue

            event_id = normalize_id(
                row.get("event_uuid", "")
            )

            if not event_id:
                continue

            anomaly_records[event_id] = {

                "command_line": row.get("command_line", ""),

                "timestamp": row.get("timestamp", ""),

                "ai_anomaly_score": row.get(
                    "ai_anomaly_score", ""
                )

            }

    # Prepare provenance counts

    provenance_counts = {}

    if not provenance_df.empty:

        required_columns = {
            "target_event_uuid",
            "relationship_type"
        }

        if required_columns.issubset(provenance_df.columns):

            related_df = provenance_df[
                provenance_df["relationship_type"] != "TARGET_EVENT"
            ]

            provenance_counts = (
                related_df.groupby(
                    "target_event_uuid"
                ).size().to_dict()
            )

    # Combine flagged events

    all_event_ids = (
        set(rule_records.keys())
        | set(anomaly_records.keys())
    )

    results = []

    for event_id in all_event_ids:

        rule_data = rule_records.get(event_id, {})

        anomaly_data = anomaly_records.get(event_id, {})

        matched_rules = rule_data.get("matched_rules", "")

        risk_score = calculate_rule_risk(matched_rules)

        if event_id in anomaly_records:
            risk_score = max(risk_score, 40)

        if risk_score >= 70:
            risk_level = "HIGH"

        elif risk_score >= 40:
            risk_level = "MEDIUM"

        else:
            risk_level = "LOW"

        action = recommend_action(risk_level)

        command = rule_data.get(
            "command_line",
            anomaly_data.get("command_line", "")
        )

        timestamp = rule_data.get(
            "timestamp",
            anomaly_data.get("timestamp", "")
        )

        host_id = rule_data.get("host_id", "")

        related_count = provenance_counts.get(event_id, 0)

        results.append({

            "event_uuid": event_id,

            "timestamp": timestamp,

            "host_id": host_id,

            "command_line": command,

            "matched_rules": matched_rules,

            "ai_anomaly": (
                "YES" if event_id in anomaly_records else "NO"
            ),

            "ai_anomaly_score": anomaly_data.get(
                "ai_anomaly_score", ""
            ),

            "related_event_count": related_count,

            "risk_score": risk_score,

            "risk_level": risk_level,

            "recommended_decision": action,

            "analyst_approval_required": "YES"

        })

    result_df = pd.DataFrame(results)

    if not result_df.empty:

        result_df = result_df.sort_values(
            by="risk_score",
            ascending=False
        )

    result_df.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    high = 0
    medium = 0
    low = 0

    if not result_df.empty:

        high = int(
            (result_df["risk_level"] == "HIGH").sum()
        )

        medium = int(
            (result_df["risk_level"] == "MEDIUM").sum()
        )

        low = int(
            (result_df["risk_level"] == "LOW").sum()
        )

    print("\n--- Risk Assessment Summary ---")

    print("Unique flagged events:", len(result_df))

    print("HIGH risk:", high)

    print("MEDIUM risk:", medium)

    print("LOW risk:", low)

    print("Analyst approval required: Yes")

    print("\nResults saved to:", OUTPUT_FILE)


if __name__ == "__main__":

    run_risk_assessment(1, 100)