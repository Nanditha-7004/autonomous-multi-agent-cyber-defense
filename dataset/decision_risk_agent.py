import csv
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DETECTION_FILE = BASE_DIR / "detection_results.csv"
AI_FILE = BASE_DIR / "ai_anomaly_results.csv"
INVESTIGATION_FILE = BASE_DIR / "provenance_investigation.csv"

OUTPUT_FILE = BASE_DIR / "risk_assessment_results.csv"


# --------------------------------------------------
# FUNCTION 1: NORMALIZE VALUES
# --------------------------------------------------

def normalize(value):

    if value is None or pd.isna(value):
        return ""

    return str(value).strip()


def normalize_uuid(value):

    return normalize(value).upper()


def find_value(row, *names):

    lookup = {
        str(key).strip().lower(): value
        for key, value in row.items()
    }

    for name in names:

        value = lookup.get(name.lower())

        if normalize(value):
            return normalize(value)

    return ""


# --------------------------------------------------
# FUNCTION 2: PROCESS DETECTION RULES
# --------------------------------------------------

def split_rules(value):

    if not value:
        return []

    rules = []

    for item in value.replace(";", ",").split(","):

        item = item.strip().upper()

        if item and item.lower() not in {
            "none", "nan", "no match"
        }:

            rules.append(item)

    return list(dict.fromkeys(rules))


# --------------------------------------------------
# FUNCTION 3: CALCULATE RULE-BASED RISK
# --------------------------------------------------

def get_rule_risk(rule):

    rule = rule.upper()

    if any(word in rule for word in (
        "DESTRUCTIVE",
        "PERSISTENCE",
        "PROCESS_INJECTION",
        "MEMORY_INJECTION"
    )):

        return 80, "HIGH"

    if any(word in rule for word in (
        "PRIVILEGED_COMMAND",
        "CREDENTIAL",
        "SUSPICIOUS_NETWORK"
    )):

        return 60, "MEDIUM"

    if any(word in rule for word in (
        "SHELL",
        "DOWNLOAD",
        "NETWORK_UTILITY"
    )):

        return 40, "MEDIUM"

    return 20, "LOW"


# --------------------------------------------------
# FUNCTION 4: READ AI ANOMALY RESULTS
# --------------------------------------------------

def get_ai_prediction(row):

    prediction = find_value(
        row,
        "ai_prediction",
        "prediction",
        "anomaly_label"
    ).upper()

    score_text = find_value(
        row,
        "ai_anomaly_score",
        "anomaly_score",
        "score"
    )

    try:

        score = float(score_text)

    except (TypeError, ValueError):

        score = None

    is_anomaly = prediction in {
        "ANOMALY",
        "-1",
        "TRUE",
        "YES"
    }

    # Use score only if explicit prediction is unavailable
    if not prediction and score is not None:

        is_anomaly = score < 0

    return is_anomaly, prediction, score


# --------------------------------------------------
# FUNCTION 5: RECOMMEND ACTION
# --------------------------------------------------

def recommend_action(rules, is_anomaly, related_events):

    rule_text = " ".join(rules).upper()

    actions = []

    if any(word in rule_text for word in (
        "PROCESS_INJECTION",
        "MEMORY_INJECTION"
    )):

        actions.append(
            "Inspect the target process, memory activity, parent "
            "process, and nearby execution events. If injection is "
            "confirmed, recommend isolating the affected process "
            "after approval."
        )

    if any(word in rule_text for word in (
        "PRIVILEGED_COMMAND",
        "PRIVILEGED"
    )):

        actions.append(
            "Verify whether elevated privileges were authorized. "
            "Review the command, account, script origin, and subsequent "
            "activity. If unauthorized, recommend restricting the "
            "account after approval."
        )

    if any(word in rule_text for word in (
        "DOWNLOAD",
        "NETWORK",
        "CONNECT"
    )):

        actions.append(
            "Inspect network connections, destination addresses, "
            "downloaded files, and subsequent executions. If a "
            "malicious destination or payload is confirmed, recommend "
            "blocking the destination and quarantining the file "
            "after approval."
        )

    if any(word in rule_text for word in (
        "SHELL",
        "EXECUTE",
        "SCRIPT"
    )):

        actions.append(
            "Inspect the command, script contents, parent process, "
            "file origin, and subsequent events. If malicious activity "
            "is confirmed, recommend stopping the related process "
            "after approval."
        )

    if any(word in rule_text for word in (
        "PERSISTENCE",
        "STARTUP",
        "CRON",
        "SERVICE"
    )):

        actions.append(
            "Check startup entries, scheduled tasks, services, and "
            "configuration changes. If unauthorized persistence is "
            "confirmed, recommend removing the malicious entry after "
            "preserving evidence and obtaining approval."
        )

    if any(word in rule_text for word in (
        "CREDENTIAL",
        "PASSWORD"
    )):

        actions.append(
            "Review authentication logs and possible credential "
            "access. If compromise is confirmed, recommend revoking "
            "affected sessions and resetting impacted credentials."
        )

    if is_anomaly:

        actions.append(
            "Review the AI-flagged event, its timestamp, command, "
            "and related activity. Compare it with normal behavior "
            "before deciding whether it represents an attack."
        )

    if related_events:

        actions.append(
            f"Review {related_events} related investigation records "
            "to understand event order and process relationships."
        )

    if not actions:

        actions.append(
            "Review the event details and surrounding activity. "
            "Collect evidence and continue monitoring before deciding "
            "whether containment is necessary."
        )

    return " ".join(actions)


# --------------------------------------------------
# FUNCTION 6: RUN INTEGRATED RISK ASSESSMENT
# --------------------------------------------------

def run_risk_assessment(
    detections_df,
    ai_df,
    investigation_df
):

    if detections_df.empty and ai_df.empty:

        raise ValueError(
            "No detection or AI anomaly results are available."
        )

    # Convert DataFrames into records
    detections = detections_df.to_dict("records")

    ai_rows = ai_df.to_dict("records")

    investigation_rows = investigation_df.to_dict("records")

    # --------------------------------------------------
    # INDEX AI RESULTS BY EVENT UUID
    # --------------------------------------------------

    ai_by_uuid = {}

    for row in ai_rows:

        event_id = normalize_uuid(
            find_value(
                row,
                "event_uuid",
                "event_id",
                "uuid"
            )
        )

        if event_id:

            ai_by_uuid[event_id] = row

    # --------------------------------------------------
    # COUNT INVESTIGATION RECORDS
    # --------------------------------------------------

    investigation_by_uuid = {}

    for row in investigation_rows:

        target_event_id = normalize_uuid(
            find_value(
                row,
                "target_event_uuid",
                "target_event_id"
            )
        )

        if target_event_id:

            investigation_by_uuid[target_event_id] = (
                investigation_by_uuid.get(target_event_id, 0) + 1
            )

    # --------------------------------------------------
    # COMBINE DETECTION AND AI RESULTS
    # --------------------------------------------------

    events_to_assess = {}

    # Add rule-based detection records
    for row in detections:

        event_id = normalize_uuid(
            find_value(
                row,
                "event_uuid",
                "event_id",
                "uuid"
            )
        )

        command = find_value(
            row,
            "command_line",
            "command"
        )

        rules = split_rules(
            find_value(
                row,
                "matched_rules",
                "rule_matches",
                "matched_rule",
                "rule_name",
                "rule"
            )
        )

        # Prefer event UUID for matching
        key = event_id or (
            f"ROW:{row.get('_source_row', len(events_to_assess))}"
        )

        if key not in events_to_assess:

            events_to_assess[key] = {
                "event_uuid": event_id,
                "command_line": command,
                "rules": []
            }

        events_to_assess[key]["rules"].extend(rules)

    # Add AI anomalies that may not have matched any rule
    for index, row in enumerate(ai_rows):

        event_id = normalize_uuid(
            find_value(
                row,
                "event_uuid",
                "event_id",
                "uuid"
            )
        )

        is_anomaly, _, _ = get_ai_prediction(row)

        if not is_anomaly:
            continue

        command = find_value(
            row,
            "command_line",
            "command"
        )

        key = event_id or (
            f"AI_ROW:{index}"
        )

        if key not in events_to_assess:

            events_to_assess[key] = {
                "event_uuid": event_id,
                "command_line": command,
                "rules": []
            }

        if not events_to_assess[key]["command_line"]:

            events_to_assess[key]["command_line"] = command

    # --------------------------------------------------
    # CALCULATE RISK FOR EACH EVENT
    # --------------------------------------------------

    output_rows = []

    for key, event in events_to_assess.items():

        event_id = event["event_uuid"]

        command = event["command_line"]

        rules = list(dict.fromkeys(event["rules"]))

        # Find matching AI record
        ai_row = ai_by_uuid.get(event_id, {})

        is_anomaly, prediction, ai_score = (
            get_ai_prediction(ai_row)
        )

        # Only assess rule matches or AI anomalies
        if not rules and not is_anomaly:
            continue

        # Calculate preliminary risk score
        rule_assessments = [
            get_rule_risk(rule)
            for rule in rules
        ]

        risk_score = max(
            (score for score, _ in rule_assessments),
            default=0
        )

        # AI anomaly increases minimum risk to 40
        if is_anomaly:

            risk_score = max(risk_score, 40)

        risk_score = min(risk_score, 100)

        # Assign risk level
        if risk_score >= 70:

            risk_level = "HIGH"

            decision = "URGENT_ANALYST_REVIEW"

        elif risk_score >= 40:

            risk_level = "MEDIUM"

            decision = "INVESTIGATE"

        else:

            risk_level = "LOW"

            decision = "MONITOR"

        # Find related investigation records
        related_count = investigation_by_uuid.get(
            event_id,
            0
        )

        # Generate recommended action
        action = recommend_action(
            rules,
            is_anomaly,
            related_count
        )

        if rules:

            matched_rule = "; ".join(rules)

        elif is_anomaly:

            matched_rule = "AI_ANOMALY"

        else:

            matched_rule = "NONE"

        output_rows.append({

            "assessment_time_utc": datetime.now(
                timezone.utc
            ).isoformat(),

            "event_uuid": event_id,

            "command_line": command[:300],

            "matched_rule": matched_rule,

            "ai_prediction": prediction or (
                "ANOMALY" if is_anomaly else "NOT_LINKED"
            ),

            "ai_anomaly_score": (
                ai_score if ai_score is not None else ""
            ),

            "risk_score": risk_score,

            "risk_level": risk_level,

            "decision": decision,

            "decision_reason": (
                "Rule matches: "
                + (", ".join(rules) if rules else "none")
                + f"; AI anomaly: {is_anomaly}."
            ),

            "related_investigation_records": related_count,

            "recommended_action": action,

            "approval_required": "YES",

            "execution_status": "NOT_EXECUTED"

        })

    columns = [
        "assessment_time_utc",
        "event_uuid",
        "command_line",
        "matched_rule",
        "ai_prediction",
        "ai_anomaly_score",
        "risk_score",
        "risk_level",
        "decision",
        "decision_reason",
        "related_investigation_records",
        "recommended_action",
        "approval_required",
        "execution_status"
    ]

    return pd.DataFrame(output_rows, columns=columns)


# --------------------------------------------------
# FUNCTION 7: INDEPENDENT SCRIPT EXECUTION
# --------------------------------------------------

def read_csv(path):

    if not path.exists():

        print("WARNING: File not found:", path)

        return pd.DataFrame()

    try:

        return pd.read_csv(path)

    except (OSError, pd.errors.ParserError) as error:

        print("ERROR reading", path.name, ":", error)

        return pd.DataFrame()


def main():

    print("\nStarting integrated Risk Assessment Agent...")

    # Read previous agent results
    detections = read_csv(DETECTION_FILE)

    ai_rows = read_csv(AI_FILE)

    investigation_rows = read_csv(INVESTIGATION_FILE)

    try:

        results = run_risk_assessment(
            detections,
            ai_rows,
            investigation_rows
        )

    except ValueError as error:

        print("ERROR:", error)

        return

    # Save results
    results.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    # Display summary
    print("\n--- Risk Assessment Summary ---")

    print(
        "Rule-based detection records loaded:",
        len(detections)
    )

    print(
        "AI anomaly records loaded:",
        len(ai_rows)
    )

    print(
        "Investigation records loaded:",
        len(investigation_rows)
    )

    print(
        "Risk assessments generated:",
        len(results)
    )

    for level in ("HIGH", "MEDIUM", "LOW"):

        count = (
            results["risk_level"] == level
        ).sum()

        print(f"{level} risk:", count)

    linked_assessments = (
        results["related_investigation_records"] > 0
    ).sum()

    print(
        "Assessments linked to investigation records:",
        linked_assessments
    )

    print("Automatic system changes: None")

    print("Analyst approval required: Yes")

    print(
        "Detailed results saved to:",
        OUTPUT_FILE
    )

    print("Risk assessment completed.")

    print(
        "\nNote: Risk scores are preliminary. "
        "Alerts require investigation and do not prove an attack."
    )


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

if __name__ == "__main__":

    main()