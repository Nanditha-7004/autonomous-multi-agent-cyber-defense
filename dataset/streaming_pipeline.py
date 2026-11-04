import time
import sys
from pathlib import Path

import streaming_rule_detection
import streaming_ai_anomaly
import streaming_provenance
import streaming_risk_assessment
import streaming_mitigation

import batch_config


def run_agent(agent_name, agent_function, start_record, end_record):

    print("\n" + "-" * 55)
    print(f"STARTING: {agent_name}")
    print("-" * 55)

    start_time = time.time()

    try:

        agent_function(start_record, end_record)

        elapsed = time.time() - start_time

        print(f"\n{agent_name} completed successfully.")
        print(f"Execution time: {elapsed:.2f} seconds")

        return True

    except Exception as error:

        print(f"\nERROR in {agent_name}: {error}")

        return False


def run_complete_pipeline(batch_number):

    start_record, end_record = batch_config.get_batch_range(
        batch_number
    )

    batch_name = batch_config.get_batch_name(batch_number)

    output_dir = (
        batch_config.BASE_DIR
        / "batch_results"
        / f"batch_{batch_number:03d}"
    )

    output_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 55)
    print("AUTONOMOUS MULTI-AGENT CYBER DEFENSE SYSTEM")
    print("=" * 55)

    print("Selected:", batch_name)
    print("Starting record:", start_record)
    print("Ending record:", end_record)

    # Configure dataset and output paths
    for module in [
        streaming_rule_detection,
        streaming_ai_anomaly,
        streaming_provenance
    ]:

        module.DATASET_FILE = batch_config.DATASET_FILE

    streaming_rule_detection.OUTPUT_FILE = (
        output_dir / "streaming_detection_results.csv"
    )

    streaming_ai_anomaly.FEATURE_FILE = (
        output_dir / "streaming_ai_features.csv"
    )

    streaming_ai_anomaly.OUTPUT_FILE = (
        output_dir / "streaming_ai_anomaly_results.csv"
    )

    streaming_provenance.DETECTION_FILE = (
        streaming_rule_detection.OUTPUT_FILE
    )

    streaming_provenance.ANOMALY_FILE = (
        streaming_ai_anomaly.OUTPUT_FILE
    )

    streaming_provenance.OUTPUT_FILE = (
        output_dir / "streaming_provenance_results.csv"
    )

    streaming_risk_assessment.DETECTION_FILE = (
        streaming_rule_detection.OUTPUT_FILE
    )

    streaming_risk_assessment.ANOMALY_FILE = (
        streaming_ai_anomaly.OUTPUT_FILE
    )

    streaming_risk_assessment.PROVENANCE_FILE = (
        streaming_provenance.OUTPUT_FILE
    )

    streaming_risk_assessment.OUTPUT_FILE = (
        output_dir / "streaming_risk_assessment_results.csv"
    )

    streaming_mitigation.RISK_FILE = (
        streaming_risk_assessment.OUTPUT_FILE
    )

    streaming_mitigation.PROVENANCE_FILE = (
        streaming_provenance.OUTPUT_FILE
    )

    streaming_mitigation.OUTPUT_FILE = (
        output_dir / "streaming_mitigation_recommendations.csv"
    )

    agents = [

        (
            "AGENT 1: RULE-BASED DETECTION",
            streaming_rule_detection.run_streaming_detection
        ),

        (
            "AGENT 2: AI ANOMALY DETECTION",
            streaming_ai_anomaly.run_streaming_ai_detection
        ),

        (
            "AGENT 3: PROVENANCE INVESTIGATION",
            streaming_provenance.run_streaming_provenance
        ),

        (
            "AGENT 4: RISK ASSESSMENT",
            streaming_risk_assessment.run_risk_assessment
        ),

        (
            "AGENT 5: MITIGATION RECOMMENDATIONS",
            streaming_mitigation.run_mitigation
        )

    ]

    pipeline_start = time.time()

    results = {}

    for agent_name, agent_function in agents:

        success = run_agent(
            agent_name,
            agent_function,
            start_record,
            end_record
        )

        results[agent_name] = (
            "SUCCESS" if success else "FAILED"
        )

        if not success:

            print("\nPipeline stopped because an agent failed.")

            break

    total_time = time.time() - pipeline_start

    print("\n" + "=" * 55)
    print("PIPELINE EXECUTION SUMMARY")
    print("=" * 55)

    for agent, status in results.items():

        print(f"{agent}: {status}")

    print(f"\nTotal execution time: {total_time:.2f} seconds")

    if len(results) == 5 and all(
        status == "SUCCESS" for status in results.values()
    ):

        print("\nCOMPLETE ANALYSIS FINISHED")

    else:

        print("\nPIPELINE INCOMPLETE - CHECK ERRORS")

    print("Results folder:", output_dir)

    print("=" * 55)


if __name__ == "__main__":

    if len(sys.argv) < 2:

        print("Usage: python streaming_pipeline.py <batch_number>")
        sys.exit(1)

    batch_number = int(sys.argv[1])

    run_complete_pipeline(batch_number)