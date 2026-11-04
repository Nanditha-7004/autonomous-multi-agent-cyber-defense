import json
from pathlib import Path
from collections import Counter

# Original DARPA dataset
BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = BASE_DIR / "ta1-theia-e3-official-3.json"

BATCH_SIZE = 5000

def test_streaming():

    print("Starting streaming test...")

    if not DATASET_FILE.exists():
        print("ERROR: Dataset not found.")
        return

    total_records = 0
    valid_records = 0
    event_types = Counter()

    with open(DATASET_FILE, "r", encoding="utf-8") as file:

        while True:

            batch = []

            # Read only 5,000 lines at a time
            for _ in range(BATCH_SIZE):

                line = file.readline()

                if not line:
                    break

                total_records += 1

                try:
                    record = json.loads(line)
                    batch.append(record)
                    valid_records += 1

                except json.JSONDecodeError:
                    continue

            if not batch:
                break

            # Inspect event types in the current batch
            for record in batch:

                datum = record.get("datum", {})

                if isinstance(datum, dict):

                    for name, event in datum.items():

                        if name.endswith(".Event"):
                            event_type = event.get("type", "UNKNOWN")
                            event_types[event_type] += 1

            print(
                f"Processed {total_records:,} lines | "
                f"Valid records: {valid_records:,}"
            )

            del batch

    print("\n--- Streaming Test Summary ---")

    print("Total lines:", total_records)
    print("Valid JSON records:", valid_records)

    print("\nEvent types found:")

    for event_type, count in event_types.most_common(10):
        print(event_type, ":", count)

    print("\nStreaming test completed successfully.")


if __name__ == "__main__":
    test_streaming()

