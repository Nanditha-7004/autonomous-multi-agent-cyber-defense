import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

RISK_FILE = BASE_DIR / "streaming_risk_assessment_results.csv"

PROVENANCE_FILE = BASE_DIR / "streaming_provenance_results.csv"

OUTPUT_FILE = BASE_DIR / "streaming_mitigation_recommendations.csv"


def load_file(path):

    if not path.exists():

        print("WARNING: File not found:", path.name)

        return pd.DataFrame()

    return pd.read_csv(
        path,
        dtype=str
    ).fillna("")


def recommend_action(rules, ai_anomaly, risk_level):

    rules = str(rules).upper()

    if "DESTRUCTIVE_COMMAND" in rules:

        return (
            "Potentially destructive command detected. "
            "Inspect affected files and verify authorization."
        )

    elif "PERSISTENCE_INDICATOR" in rules:

        return (
            "Investigate possible persistence mechanisms. "
            "Review scheduled tasks and startup configurations."
        )

    elif "PRIVILEGED_COMMAND" in rules:

        return (
            "Verify whether elevated execution was authorized. "
            "Inspect script origin and related activity."
        )

    elif "DOWNLOAD_AND_EXECUTE" in rules:

        return (
            "Investigate downloaded content and its source. "
            "Review subsequent process and network activity."
        )

    elif "NETWORK_UTILITY" in rules:

        return (
            "Inspect network utility usage and destination addresses."
        )

    elif "PROCESS_DEBUGGING" in rules:

        return (
            "Investigate process debugging or tracing activity."
        )

    elif "ENCODED_COMMAND" in rules:

        return (
            "Inspect encoded commands and review their contents."
        )

    elif "SHELL_EXECUTION" in rules:

        return (
            "Inspect the executed shell command and its origin."
        )

    elif "REMOTE_ACCESS" in rules:

        return (
            "Review remote access activity and authentication context."
        )

    elif "PERMISSION_CHANGE" in rules:

        return (
            "Inspect affected files and permission changes."
        )

    elif str(ai_anomaly).upper() == "YES":

        return (
            "Unusual activity identified by the anomaly model. "
            "Review the original event and related activities."
        )

    else:

        return (
            "Review the event and collect additional context."
        )


def prepare_provenance_info(provenance_df):

    provenance_info = {}

    if provenance_df.empty:
        return provenance_info

    required_columns = {

        "target_event_uuid",

        "related_event_uuid",

        "related_event_type",

        "relationship_type"

    }

    if not required_columns.issubset(provenance_df.columns):
        return provenance_info

    related_df = provenance_df[
        provenance_df["relationship_type"] != "TARGET_EVENT"
    ].copy()

    for event_id, group in related_df.groupby(
        "target_event_uuid"
    ):

        group = group.drop_duplicates(
            subset=["related_event_uuid"]
        )

        related_types = sorted(
            set(
                event_type
                for event_type in group["related_event_type"]
                if event_type.strip()
            )
        )

        provenance_info[str(event_id)] = {

            "related_event_count": len(group),

            "related_event_types": "; ".join(related_types)

        }

    return provenance_info


def run_mitigation(start_record, end_record):

    print("\nStarting Streaming Mitigation Agent...")

    risk_df = load_file(RISK_FILE)

    provenance_df = load_file(PROVENANCE_FILE)

    if risk_df.empty:

        print("No risk assessment results available.")

        result_df = pd.DataFrame(columns=[
            "event_uuid",
            "recommended_action",
            "mitigation_priority"
        ])

        result_df.to_csv(
            OUTPUT_FILE,
            index=False
        )

        return

    provenance_info = prepare_provenance_info(
        provenance_df
    )

    recommendations = []

    for _, row in risk_df.iterrows():

        event_id = str(
            row.get("event_uuid", "")
        ).strip()

        rules = row.get("matched_rules", "")

        ai_anomaly = row.get("ai_anomaly", "NO")

        risk_level = row.get("risk_level", "LOW")

        recommendation = recommend_action(
            rules,
            ai_anomaly,
            risk_level
        )

        context = provenance_info.get(
            event_id,
            {}
        )

        related_count = context.get(
            "related_event_count",
            0
        )

        related_types = context.get(
            "related_event_types",
            ""
        )

        if related_count > 0:

            recommendation += (
                " Related event context is available. "
                "Review associated records."
            )

        if risk_level == "HIGH":

            priority = "URGENT"

        elif risk_level == "MEDIUM":

            priority = "REVIEW"

        else:

            priority = "MONITOR"

        recommendations.append({

            "event_uuid": event_id,

            "timestamp": row.get("timestamp", ""),

            "command_line": row.get("command_line", ""),

            "matched_rules": rules,

            "ai_anomaly": ai_anomaly,

            "risk_score": row.get("risk_score", ""),

            "risk_level": risk_level,

            "problem": "Suspicious activity requiring investigation",

            "recommended_action": recommendation,

            "related_event_count": related_count,

            "related_event_types": related_types,

            "mitigation_priority": priority,

            "automatic_action_taken": "NO",

            "approval_required": "YES",

            "execution_status": "PENDING_ANALYST_REVIEW"

        })

    result_df = pd.DataFrame(recommendations)

    result_df.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    urgent = int(
        (result_df["mitigation_priority"] == "URGENT").sum()
    )

    review = int(
        (result_df["mitigation_priority"] == "REVIEW").sum()
    )

    monitor = int(
        (result_df["mitigation_priority"] == "MONITOR").sum()
    )

    print("\n--- Mitigation Summary ---")

    print("Recommendations generated:", len(result_df))

    print("URGENT priority:", urgent)

    print("REVIEW priority:", review)

    print("MONITOR priority:", monitor)

    print("Automatic system changes: None")

    print("Analyst approval required: Yes")

    print("\nResults saved to:", OUTPUT_FILE)


if __name__ == "__main__":

    run_mitigation(1, 100)