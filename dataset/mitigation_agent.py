import csv
from pathlib import Path

import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

RISK_FILE = BASE_DIR / "risk_assessment_results.csv"

INVESTIGATION_FILE = BASE_DIR / "provenance_investigation.csv"

OUTPUT_FILE = BASE_DIR / "mitigation_recommendations.csv"


# --------------------------------------------------
# FUNCTION 1: NORMALIZE VALUES
# --------------------------------------------------

def normalize(value):

    if value is None or pd.isna(value):
        return ""

    return str(value).strip()


# --------------------------------------------------
# FUNCTION 2: GET RELATED COMMANDS
# --------------------------------------------------

def get_command_context(events):

    commands = []

    for event in events:

        command = normalize(
            event.get("command_line", "")
        )

        if command and command not in commands:

            commands.append(command)

    return commands


# --------------------------------------------------
# FUNCTION 3: GENERATE MITIGATION RECOMMENDATIONS
# --------------------------------------------------

def recommend_action(
    rule,
    risk,
    decision_reason,
    commands,
    event_types
):

    rule = rule.upper()

    risk = risk.upper()

    event_types = set(event_types)

    # Identify the problem and recommend an action

    if "DESTRUCTIVE_COMMAND" in rule:

        problem = "Potential destructive command"

        action = (
            "Review the command and inspect affected files. "
            "Preserve logs and check for deletion or system damage. "
            "If confirmed malicious, restrict the responsible account "
            "and restore affected files."
        )

    elif "DOWNLOAD_AND_EXECUTE" in rule:

        problem = "Potential download-and-execute activity"

        action = (
            "Identify the downloaded file and its source. "
            "Inspect file hashes and related network activity. "
            "If malicious, quarantine the file and block its source "
            "using approved security controls."
        )

    elif "NETWORK_UTILITY" in rule:

        problem = "Potential suspicious network activity"

        action = (
            "Inspect destination addresses, ports, and connection events. "
            "Identify the initiating process. If the connection is "
            "unauthorized, block the destination and investigate "
            "related systems."
        )

    elif "PROCESS_DEBUGGING" in rule:

        problem = "Potential process manipulation"

        action = (
            "Inspect the target process and associated memory events. "
            "Check for unauthorized debugging or injection. "
            "If confirmed malicious, contain the affected host and "
            "stop the process through approved response procedures."
        )

    elif "PRIVILEGED_COMMAND" in rule:

        problem = "Execution with elevated privileges"

        action = (
            "Verify whether elevated execution was authorized. "
            "Inspect the script origin, parent process, and subsequent "
            "file activity. If unauthorized, restrict the responsible "
            "account and stop the related activity after analyst approval."
        )

    elif "SHELL_EXECUTION" in rule:

        problem = "Shell script execution requiring investigation"

        action = (
            "Inspect the script contents, origin, and parent process. "
            "Review subsequent file, memory, and network events for "
            "suspicious changes. If confirmed malicious, quarantine "
            "the script and contain the affected host."
        )

    else:

        problem = "Suspicious activity requiring investigation"

        action = (
            "Review the original event and related process, file, "
            "memory, and network activity. Gather evidence before "
            "selecting a response."
        )

    # --------------------------------------------------
    # ADD INVESTIGATION CONTEXT
    # --------------------------------------------------

    if commands:

        action += (
            " Related commands: "
            + "; ".join(commands[:5])
            + "."
        )

    context = []

    for event_type in (
        "EVENT_CONNECT",
        "EVENT_RECVFROM",
        "EVENT_WRITE",
        "EVENT_OPEN",
        "EVENT_MPROTECT",
        "EVENT_EXECUTE"
    ):

        if event_type in event_types:

            context.append(event_type)

    if context:

        action += (
            " Related event types observed: "
            + ", ".join(context)
            + "."
        )

    action += (
        " Investigation note: "
        + (
            decision_reason
            or "Further contextual analysis is required."
        )
    )

    # --------------------------------------------------
    # ASSIGN MITIGATION PRIORITY
    # --------------------------------------------------

    if risk == "HIGH":

        priority = "URGENT"

        action += (
            " Prioritize analyst review and preserve evidence. "
            "Apply containment after authorization."
        )

    elif risk == "MEDIUM":

        priority = "REVIEW"

        action += (
            " Obtain analyst review before containment."
        )

    else:

        priority = "MONITOR"

        action += (
            " Monitor for recurrence and reassess "
            "if new evidence appears."
        )

    return problem, priority, action


# --------------------------------------------------
# FUNCTION 4: RUN MITIGATION RECOMMENDATIONS
# --------------------------------------------------

def run_mitigation(risk_df, investigation_df):

    if risk_df.empty:

        raise ValueError(
            "No risk assessment results are available."
        )

    risk_df = risk_df.copy()

    investigation_df = investigation_df.copy()

    # Convert investigation records into groups by target event UUID

    events_by_target = {}

    events_by_subject = {}

    for _, event in investigation_df.iterrows():

        target_id = normalize(
            event.get("target_event_uuid", "")
        ).upper()

        subject_id = normalize(
            event.get("subject_id", "")
        )

        event_data = event.to_dict()

        if target_id:

            events_by_target.setdefault(
                target_id, []
            ).append(event_data)

        if subject_id:

            events_by_subject.setdefault(
                subject_id, []
            ).append(event_data)

    results = []

    # Process each risk assessment
    for _, risk_row in risk_df.iterrows():

        risk_data = risk_row.to_dict()

        rule = normalize(
            risk_data.get("matched_rule", "")
        )

        risk = normalize(
            risk_data.get("risk_level", "MEDIUM")
        )

        reason = normalize(
            risk_data.get("decision_reason", "")
        )

        event_id = normalize(
            risk_data.get("event_uuid", "")
        ).upper()

        # Find investigation records using event UUID
        related_events = list(
            events_by_target.get(event_id, [])
        )

        # Collect related subject IDs
        subjects = {

            normalize(event.get("subject_id", ""))

            for event in related_events

            if normalize(event.get("subject_id", ""))

        }

        # Expand investigation context using subject relationships
        for subject in subjects:

            related_events.extend(
                events_by_subject.get(subject, [])
            )

        # Remove duplicate investigation events
        unique_events = {}

        for event in related_events:

            event_id_related = normalize(
                event.get("event_uuid", "")
            )

            unique_key = event_id_related or (

                normalize(event.get("timestamp", "")),

                normalize(event.get("event_type", "")),

                normalize(event.get("subject_id", "")),

                normalize(event.get("object_id", ""))

            )

            unique_events[unique_key] = event

        related_events = list(
            unique_events.values()
        )

        # Extract related commands and event types
        commands = get_command_context(
            related_events
        )

        event_types = [

            normalize(event.get("event_type", ""))

            for event in related_events

        ]

        # Generate recommendation
        problem, priority, action = recommend_action(
            rule,
            risk,
            reason,
            commands,
            event_types
        )

        results.append({

            **risk_data,

            "problem_identified": problem,

            "related_commands": "; ".join(
                commands[:5]
            ),

            "related_event_count": len(
                related_events
            ),

            "related_event_types": "; ".join(
                sorted(set(event_types))
            ),

            "mitigation_priority": priority,

            "recommended_action": action,

            "automatic_action_taken": "No",

            "approval_required": "Yes",

            "status": "Pending analyst review"

        })

    return pd.DataFrame(results)


# --------------------------------------------------
# FUNCTION 5: READ CSV FILES
# --------------------------------------------------

def read_csv(path):

    if not path.exists():

        print("WARNING: File not found:", path)

        return pd.DataFrame()

    try:

        return pd.read_csv(path)

    except (OSError, pd.errors.ParserError) as error:

        print(
            "ERROR reading",
            path.name,
            ":",
            error
        )

        return pd.DataFrame()


# --------------------------------------------------
# FUNCTION 6: INDEPENDENT SCRIPT EXECUTION
# --------------------------------------------------

def main():

    print(
        "\nStarting Context-Aware Mitigation Agent..."
    )

    # Read previous agent results
    risk_rows = read_csv(RISK_FILE)

    investigation_rows = read_csv(
        INVESTIGATION_FILE
    )

    try:

        results = run_mitigation(
            risk_rows,
            investigation_rows
        )

    except ValueError as error:

        print("ERROR:", error)

        return

    # Save recommendations
    results.to_csv(
        OUTPUT_FILE,
        index=False,
        encoding="utf-8-sig"
    )

    # Display summary
    print("\n--- Mitigation Summary ---")

    print(
        "Risk records:",
        len(risk_rows)
    )

    print(
        "Investigation events:",
        len(investigation_rows)
    )

    print(
        "Recommendations generated:",
        len(results)
    )

    print(
        "Automatic system changes: None"
    )

    print(
        "Analyst approval required: Yes"
    )

    print(
        "Report saved:",
        OUTPUT_FILE
    )

    # Display sample recommendations
    print("\n--- Sample Recommendations ---")

    for index, row in results.head(2).iterrows():

        print(
            f"\n{index + 1}. Rule:",
            row["matched_rule"]
        )

        print(
            "   Risk:",
            row["risk_level"]
        )

        print(
            "   Problem:",
            row["problem_identified"]
        )

        print(
            "   Related events:",
            row["related_event_count"]
        )

        print(
            "   Priority:",
            row["mitigation_priority"]
        )

        print(
            "   Action:",
            row["recommended_action"][:500]
        )

    print("\nMitigation completed.")

    print(
        "NOTE: Recommendations require analyst review. "
        "No actual system changes are performed."
    )


# --------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------

if __name__ == "__main__":

    main()