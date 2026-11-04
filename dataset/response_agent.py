import csv
from pathlib import Path

BASE_DIR = Path(__file__).parent

INPUT_FILE = BASE_DIR / "mitigation_recommendations.csv"
OUTPUT_FILE = BASE_DIR / "response_plan.csv"

def choose_response(rule, risk, action):
    rule = str(rule).upper()
    risk = str(risk).upper()
    action = str(action).lower()

    if "PRIVILEGED_COMMAND" in rule:
        return (
            "Verify authorization; inspect the command and script origin. "
            "If unauthorized, recommend stopping the related process "
            "after analyst approval."
        )

    if "SHELL_EXECUTION" in rule:
        return (
            "Inspect the script, parent process, and subsequent events. "
            "If malicious, recommend quarantining the script "
            "after analyst approval."
        )

    if "DESTRUCTIVE_COMMAND" in rule:
        return (
            "Inspect the command and affected files. "
            "If malicious, recommend stopping the activity and restoring "
            "verified files after approval."
        )

    if "DOWNLOAD" in rule:
        return (
            "Inspect the downloaded file and its source. "
            "If malicious, recommend quarantining the file and checking "
            "for related execution."
        )

    if risk == "HIGH":
        return (
            "Prioritize investigation, preserve evidence, and recommend "
            "isolating the affected host if malicious activity is confirmed."
        )

    if risk == "MEDIUM":
        return (
            "Review related events and monitor the activity. "
            "Escalate if additional evidence confirms malicious behavior."
        )

    return (
        "Record the event and continue monitoring. "
        "Escalate if further suspicious evidence appears."
    )


def main():
    print("Starting response planning agent...")

    if not INPUT_FILE.exists():
        print("ERROR: Mitigation report not found:", INPUT_FILE)
        print("Run mitigation_agent.py first.")
        return

    with INPUT_FILE.open("r", newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)
        records = list(reader)

    if not records:
        print("No mitigation records found.")
        return

    output_rows = []

    for record in records:
        rule = record.get("matched_rule", record.get("rule", "UNKNOWN"))
        risk = record.get("risk_level", record.get("risk", "MEDIUM"))
        action = record.get("recommended_action", record.get("action", ""))

        response = choose_response(rule, risk, action)

        output_rows.append({
            "matched_rule": rule,
            "risk_level": risk,
            "original_recommendation": action,
            "response_plan": response,
            "approval_required": "YES",
            "execution_status": "NOT_EXECUTED"
        })

    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "matched_rule",
                "risk_level",
                "original_recommendation",
                "response_plan",
                "approval_required",
                "execution_status"
            ]
        )
        writer.writeheader()
        writer.writerows(output_rows)

    print("\n--- Response Plan Summary ---")
    print("Records processed:", len(output_rows))
    print("Response plans generated:", len(output_rows))
    print("Approval required: Yes")
    print("Actions executed automatically: 0")
    print("Report saved to:", OUTPUT_FILE)

    print("\n--- First 3 Response Plans ---")

    for index, row in enumerate(output_rows[:3], start=1):
        print(f"\n{index}. Rule: {row['matched_rule']}")
        print("   Risk:", row["risk_level"])
        print("   Response:", row["response_plan"])

    print("\nResponse planning completed.")


if __name__ == "__main__":
    main()

