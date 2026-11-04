import json
from pathlib import Path
from collections import Counter

import networkx as nx

DATASET_FILE = Path(__file__).parent / "ta1-theia-e3-official-3.json"
OUTPUT_FILE = Path(__file__).parent / "provenance_graph.graphml"

UUID_KEY = "com.bbn.tc.schema.avro.cdm18.UUID"

graph = nx.MultiDiGraph()

event_counts = Counter()
edge_counts = Counter()
skipped_events = 0


def extract_uuid(value):
    """Extract a valid entity UUID, excluding missing and all-zero UUIDs."""
    if not isinstance(value, dict):
        return None

    uuid = value.get(UUID_KEY)

    if not isinstance(uuid, str) or not uuid.strip():
        return None

    # Ignore placeholder UUIDs containing only zeros and hyphens.
    if set(uuid.replace("-", "")) == {"0"}:
        return None

    return uuid


print("Building provenance graph...")
print("Dataset:", DATASET_FILE)

if not DATASET_FILE.exists():
    raise FileNotFoundError(f"Dataset not found: {DATASET_FILE}")

with DATASET_FILE.open("r", encoding="utf-8") as file:
    for line in file:
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        datum = record.get("datum", {})

        if not isinstance(datum, dict):
            continue

        for record_name, event in datum.items():
            if not record_name.endswith(".Event"):
                continue

            if not isinstance(event, dict):
                continue

            event_type = event.get("type", "UNKNOWN")
            event_counts[event_type] += 1

            subject_id = extract_uuid(event.get("subject"))
            object_id = extract_uuid(event.get("predicateObject"))
            object2_id = extract_uuid(event.get("predicateObject2"))

            timestamp = event.get("timestampNanos")
            host_id = event.get("hostId")

            timestamp = str(timestamp) if timestamp is not None else ""
            host_id = str(host_id) if host_id is not None else ""

            # Add the primary subject-to-object relationship.
            if subject_id and object_id:
                graph.add_node(subject_id, entity_type="entity")
                graph.add_node(object_id, entity_type="entity")

                graph.add_edge(
                    subject_id,
                    object_id,
                    event_type=event_type,
                    relationship="predicateObject",
                    timestamp=timestamp,
                    host_id=host_id
                )

                edge_counts[event_type] += 1
            else:
                skipped_events += 1

            # Preserve the second-object relationship when available.
            if subject_id and object2_id:
                graph.add_node(subject_id, entity_type="entity")
                graph.add_node(object2_id, entity_type="entity")

                graph.add_edge(
                    subject_id,
                    object2_id,
                    event_type=event_type,
                    relationship="predicateObject2",
                    timestamp=timestamp,
                    host_id=host_id
                )

                edge_counts[event_type] += 1

# Validate that placeholder UUIDs were excluded.
zero_uuid_nodes = [
    node for node in graph.nodes
    if isinstance(node, str)
    and set(node.replace("-", "")) == {"0"}
]

print("\n--- Provenance Graph Summary ---")
print("Nodes:", graph.number_of_nodes())
print("Edges:", graph.number_of_edges())
print("Events without a primary subject-object relationship:", skipped_events)
print("All-zero UUID nodes:", len(zero_uuid_nodes))

print("\n--- Event Type Counts ---")
for event_type, count in event_counts.most_common():
    print(f"{event_type}: {count}")

print("\n--- Graph Edge Counts by Event Type ---")
for event_type, count in edge_counts.most_common():
    print(f"{event_type}: {count}")

nx.write_graphml(graph, OUTPUT_FILE)

print("\nGraph saved to:", OUTPUT_FILE)
print("Graph construction completed.")

