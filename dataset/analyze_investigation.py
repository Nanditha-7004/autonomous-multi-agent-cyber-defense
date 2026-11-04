import pandas as pd
from pathlib import Path

INPUT_FILE = Path(__file__).parent / "provenance_investigation.csv"
OUTPUT_FILE = Path(__file__).parent / "investigation_timeline.csv"

df = pd.read_csv(INPUT_FILE)

# Sort events chronologically.
df = df.sort_values("timestamp").reset_index(drop=True)

# Mark events that deserve closer investigation.
important_events = {
    "EVENT_EXECUTE",
    "EVENT_CLONE",
    "EVENT_CONNECT",
    "EVENT_RECVFROM",
    "EVENT_SENDTO",
    "EVENT_MMAP",
    "EVENT_MPROTECT",
    "EVENT_OPEN",
    "EVENT_WRITE",
}

df["investigation_note"] = df["event_type"].apply(
    lambda event: (
        "Review execution command"
        if event == "EVENT_EXECUTE"
        else "Review memory activity"
        if event in {"EVENT_MMAP", "EVENT_MPROTECT"}
        else "Review process creation"
        if event == "EVENT_CLONE"
        else "Review network activity"
        if event in {"EVENT_CONNECT", "EVENT_RECVFROM", "EVENT_SENDTO"}
        else "Review file activity"
        if event in {"EVENT_OPEN", "EVENT_WRITE"}
        else "Other event"
    )
)

df.to_csv(OUTPUT_FILE, index=False)

print("Investigation timeline created.")
print("Total events:", len(df))
print("\nEvent summary:")
print(df["event_type"].value_counts().to_string())

print("\nExecution events:")
print(
    df.loc[
        df["event_type"] == "EVENT_EXECUTE",
        ["timestamp", "command_line", "investigation_note"],
    ].to_string(index=False)
)

print("\nTimeline saved to:", OUTPUT_FILE)

