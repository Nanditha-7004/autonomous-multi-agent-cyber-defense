import csv
import re
from pathlib import Path
from collections import Counter

import pandas as pd


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "execution_events.csv"
OUTPUT_FILE = BASE_DIR / "detection_results.csv"


# --------------------------------------------------
# EXISTING 10 DETECTION RULES
# --------------------------------------------------

RULES = [
    (
        "DOWNLOAD_AND_EXECUTE",
        re.compile(
            r"\b(?:curl|wget)\b.{0,500}?(?:\|\s*(?:sh|bash)\b|"
            r"(?:sh|bash)\s+-c\b)",
            re.IGNORECASE,
        ),
        "Possible download-and-execute command pattern.",
        8,
    ),
    (
        "NETWORK_UTILITY",
        re.compile(
            r"(?:^|[\s/])(?:nc|ncat|netcat|socat)(?:\s|$)",
            re.IGNORECASE,
        ),
        "Network utility detected; investigate its context.",
        4,
    ),
    (
        "PROCESS_DEBUGGING",
        re.compile(
            r"\b(?:gdb|gcore|ptrace|strace|ltrace)\b",
            re.IGNORECASE,
        ),
        "Process debugging or tracing utility detected.",
        5,
    ),
    (
        "PRIVILEGED_COMMAND",
        re.compile(
            r"(?:^|[;&|]\s*|\s)(?:sudo|su)(?:\s|$)",
            re.IGNORECASE,
        ),
        "Privileged command detected; verify whether it is expected.",
        3,
    ),
    (
        "ENCODED_COMMAND",
        re.compile(
            r"\b(?:base64\s+-d|base64\s+--decode|"
            r"python(?:3)?\s+-c|perl\s+-e|ruby\s+-e)\b",
            re.IGNORECASE,
        ),
        "Encoded data or inline script execution detected; inspect context.",
        4,
    ),
    (
        "SHELL_EXECUTION",
        re.compile(
            r"\b(?:bash|sh|dash|zsh)\s+-c\b",
            re.IGNORECASE,
        ),
        "Shell command passed as an argument; inspect the executed content.",
        3,
    ),
    (
        "PERSISTENCE_INDICATOR",
        re.compile(
            r"(?:\bcrontab\b|\b(?:systemctl|service)\s+enable\b|"
            r"/etc/cron\.(?:d|daily|hourly|weekly|monthly)/|"
            r"/etc/rc\.local\b|~?/.ssh/authorized_keys)",
            re.IGNORECASE,
        ),
        "Possible persistence-related command or path detected.",
        7,
    ),
    (
        "REMOTE_ACCESS",
        re.compile(
            r"\b(?:ssh|scp|sftp)\b",
            re.IGNORECASE,
        ),
        "Remote-access utility detected; verify destination and context.",
        3,
    ),
    (
        "PERMISSION_CHANGE",
        re.compile(
            r"\bchmod\s+(?:[0-7]{3,4}|[ugoar]*[+=-][rwxXstugo]+)\b",
            re.IGNORECASE,
        ),
        "File permission change detected; inspect target and context.",
        3,
    ),
    (
        "DESTRUCTIVE_COMMAND",
        re.compile(
            r"\brm\s+(?:-[a-zA-Z]*r[a-zA-Z]*f?|"
            r"-[a-zA-Z]*f[a-zA-Z]*r?)\b",
            re.IGNORECASE,
        ),
        "Potentially destructive file-removal command detected.",
        5,
    ),
]


# --------------------------------------------------
# FUNCTION 1: ANALYSE ONE COMMAND
# --------------------------------------------------

def analyze_command(command):

    matches = []

    if not command:
        return matches

    for rule_name, pattern, explanation, score in RULES:

        if pattern.search(str(command)):

            matches.append({
                "rule": rule_name,
                "reason": explanation,
                "score": score,
            })

    return matches


# --------------------------------------------------
# FUNCTION 2: RUN DETECTION ON UPLOADED DATA
# --------------------------------------------------

def run_detection(df):

    if df.empty:
        raise ValueError("Uploaded dataset is empty.")

    if "command_line" not in df.columns:
        raise ValueError(
            "Rule-based detection requires a command_line column."
        )

    results = []

    for _, row in df.iterrows():

        command = str(row.get("command_line", "") or "").strip()

        matches = analyze_command(command)

        score = min(
            sum(item["score"] for item in matches),
            10
        )

        if score >= 8:
            severity = "HIGH"

        elif score >= 5:
            severity = "MEDIUM"

        elif score > 0:
            severity = "LOW"

        else:
            severity = "NONE"

        status = (
            "REVIEW_REQUIRED"
            if matches
            else "NO_RULE_MATCH"
        )

        results.append({

            "event_uuid": row.get("event_uuid", ""),

            "timestamp": row.get("timestamp", ""),

            "host_id": row.get("host_id", ""),

            "command_line": command,

            "matched_rules": "; ".join(
                item["rule"] for item in matches
            ),

            "reasons": "; ".join(
                item["reason"] for item in matches
            ),

            "risk_score": score,

            "severity": severity,

            "status": status

        })

    return pd.DataFrame(results)


# --------------------------------------------------
# FUNCTION 3: INDEPENDENT SCRIPT EXECUTION
# --------------------------------------------------

def main():

    if not INPUT_FILE.exists():

        print("ERROR: Input file not found:", INPUT_FILE)

        return

    df = pd.read_csv(INPUT_FILE)

    try:

        results = run_detection(df)

    except ValueError as error:

        print("ERROR:", error)

        return

    results.to_csv(OUTPUT_FILE, index=False)

    flagged = results[
        results["status"] == "REVIEW_REQUIRED"
    ]

    print("\n--- Detection Summary ---")

    print("Events analysed:", len(results))

    print("Events requiring review:", len(flagged))

    print(
        "Events with no rule match:",
        len(results) - len(flagged)
    )

    print("\nRule matches:")

    rule_counts = Counter()

    for rules in results["matched_rules"]:

        for rule in str(rules).split(";"):

            rule = rule.strip()

            if rule:
                rule_counts[rule] += 1

    for rule, count in sorted(rule_counts.items()):

        print(f"{rule}: {count}")

    print("\nResults saved to:", OUTPUT_FILE)

    print(
        "IMPORTANT: Rule matches are investigation leads, "
        "not proof of malicious activity."
    )


if __name__ == "__main__":
    main()