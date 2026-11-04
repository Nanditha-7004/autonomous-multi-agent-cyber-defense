import csv
from collections import Counter, defaultdict

INPUT_FILE = "detection_results.csv"
OUTPUT_FILE = "investigation_summary.csv"

total_events = 0
flagged_events = 0

rule_counts = Counter()
command_counts = Counter()
rule_commands = defaultdict(Counter)

print("Analyzing execution events and detection rules...")

with open(INPUT_FILE, "r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total_events += 1

        command = row.get("command_line", "").strip()
        matched_rules = row.get("matched_rules", "").strip()

        if row.get("status") != "REVIEW_REQUIRED":
            continue

        flagged_events += 1

        if not command:
            command = "(empty command)"

        command_counts[command] += 1

        rules = [
            rule.strip()
            for rule in matched_rules.split(";")
            if rule.strip()
        ]

        for rule in rules:
            rule_counts[rule] += 1
            rule_commands[rule][command] += 1

print("\n--- Investigation Results ---")
print("Total events analyzed:", total_events)
print("Events requiring review:", flagged_events)
print("Distinct flagged commands:", len(command_counts))

print("\n--- Rule Frequency ---")
for rule, count in rule_counts.most_common():
    print(f"{rule}: {count} matching events")

print("\n--- Top 10 Repeated Commands ---")
for command, count in command_counts.most_common(10):
    print(f"{count} occurrences | {command}")

print("\n--- Less Frequent Flagged Commands ---")
less_frequent = [
    (command, count)
    for command, count in command_counts.items()
    if count <= 2
]

for command, count in sorted(less_frequent, key=lambda item: item[1]):
    print(f"{count} occurrence(s) | {command}")

with open(
    OUTPUT_FILE, "w", encoding="utf-8", newline=""
) as file:
    writer = csv.writer(file)

    writer.writerow([
        "category",
        "rule",
        "command",
        "occurrences",
        "interpretation"
    ])

    for rule, count in rule_counts.most_common():
        common_commands = rule_commands[rule].most_common(10)

        for command, occurrences in common_commands:
            writer.writerow([
                "RULE_MATCH",
                rule,
                command,
                occurrences,
                "Requires contextual investigation; not a confirmed attack"
            ])

    for command, count in command_counts.most_common():
        writer.writerow([
            "COMMAND_FREQUENCY",
            "",
            command,
            count,
            "Frequency alone does not establish whether activity is malicious"
        ])

print("\nDetailed results saved to:", OUTPUT_FILE)
print("Reminder: Rule matches are not confirmed attacks.")

