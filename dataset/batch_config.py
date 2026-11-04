import math
from pathlib import Path

TOTAL_BATCHES = 20

BASE_DIR = Path(__file__).resolve().parent

DATASET_FILE = BASE_DIR / "ta1-theia-e3-official-3.json"


def count_records():

    if not DATASET_FILE.exists():
        raise FileNotFoundError("DARPA dataset not found.")

    count = 0

    with open(DATASET_FILE, "r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                count += 1

    return count


def get_batch_range(batch_number):

    if batch_number < 1 or batch_number > TOTAL_BATCHES:
        raise ValueError("Invalid batch number.")

    total_records = count_records()

    records_per_batch = math.ceil(
        total_records / TOTAL_BATCHES
    )

    start_record = (
        (batch_number - 1) * records_per_batch
    ) + 1

    end_record = min(
        batch_number * records_per_batch,
        total_records
    )

    return start_record, end_record


def get_batch_name(batch_number):

    return f"Dataset Batch {batch_number:03d}"