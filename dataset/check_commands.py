import csv

filename = "execution_events.csv"

total = 0
commands_found = 0

print("Checking extracted command lines...\n")

with open(filename, "r", encoding="utf-8", newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        total += 1
        command = row.get("command_line", "").strip()

        if command:
            commands_found += 1

            if commands_found <= 10:
                print("Command:", command)

print("\n--- Summary ---")
print("Total execution events:", total)
print("Events with commands:", commands_found)
print("Events without commands:", total - commands_found)

