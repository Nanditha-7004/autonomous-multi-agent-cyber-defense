import streamlit as st
import pandas as pd
import subprocess
import sys
from pathlib import Path
import math
import time
import json
import threading
import psutil

# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Autonomous Cyber Defense System",
    page_icon="🛡️",
    layout="wide"
)

# ==================================================
# PROJECT PATHS
# ==================================================

BASE_DIR = Path(__file__).resolve().parent

DATASET_DIR = BASE_DIR / "dataset"

DATASET_FILE = DATASET_DIR / "ta1-theia-e3-official-3.json"

PIPELINE_FILE = DATASET_DIR / "streaming_pipeline.py"

RESULT_DIR = DATASET_DIR / "batch_results"

TOTAL_BATCHES = 20

# Performance results are saved separately for each batch.
PERFORMANCE_FILENAME = "performance_metrics.json"

# ==================================================
# AGENT OUTPUT FILES
# ==================================================

AGENTS = {
    "Rule-Based Detection": "streaming_detection_results.csv",

    "AI Anomaly Detection": "streaming_ai_anomaly_results.csv",

    "Provenance Investigation": "streaming_provenance_results.csv",

    "Risk Assessment": "streaming_risk_assessment_results.csv",

    "Mitigation Recommendations": "streaming_mitigation_recommendations.csv"
}

# ==================================================
# SESSION STATE
# ==================================================

if "selected_batch" not in st.session_state:
    st.session_state.selected_batch = 1

if "pipeline_logs" not in st.session_state:
    st.session_state.pipeline_logs = ""

if "pipeline_running" not in st.session_state:
    st.session_state.pipeline_running = False

if "last_performance" not in st.session_state:
    st.session_state.last_performance = None

# ==================================================
# DATASET VALIDATION
# ==================================================

if not DATASET_FILE.exists():

    st.error(
        "DARPA dataset not found. Please check the dataset folder."
    )

    st.stop()

if not PIPELINE_FILE.exists():

    st.error(
        "Streaming pipeline file not found."
    )

    st.stop()

# ==================================================
# COUNT DATASET RECORDS
# ==================================================

@st.cache_data
def count_records(file_path, modified_time):

    count = 0

    with open(
        file_path,
        "r",
        encoding="utf-8"
    ) as file:

        for line in file:

            if line.strip():
                count += 1

    return count


total_records = count_records(
    str(DATASET_FILE),
    DATASET_FILE.stat().st_mtime
)

# ==================================================
# BATCH RANGE
# ==================================================

def get_batch_range(batch_number):

    if total_records == 0:
        return 0, 0

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


# ==================================================
# RESULT FOLDER
# ==================================================

def get_result_folder(batch_number):

    return (
        RESULT_DIR /
        f"batch_{batch_number:03d}"
    )


# ==================================================
# LOAD AGENT RESULTS
# ==================================================

def load_agent_result(batch_number, filename):

    file_path = (
        get_result_folder(batch_number) /
        filename
    )

    if not file_path.exists():
        return None

    try:

        return pd.read_csv(
            file_path,
            low_memory=False
        )

    except Exception as error:

        st.error(
            f"Error loading {filename}: {error}"
        )

        return None


# ==================================================
# PERFORMANCE MONITORING
# ==================================================

def get_process_tree_memory_mb(process_pid):
    """
    Return the combined RAM usage of the pipeline process
    and its child processes, in MB.
    """

    total_memory = 0

    try:

        parent = psutil.Process(process_pid)

        processes = [parent] + parent.children(recursive=True)

        for proc in processes:

            try:

                total_memory += proc.memory_info().rss

            except (psutil.NoSuchProcess, psutil.AccessDenied):

                continue

    except (psutil.NoSuchProcess, psutil.AccessDenied):

        pass

    return total_memory / (1024 * 1024)


def monitor_peak_memory(process_pid, stop_event, memory_values):
    """
    Sample pipeline process-tree memory periodically and
    retain the highest observed value.
    """

    while not stop_event.is_set():

        memory_mb = get_process_tree_memory_mb(process_pid)

        memory_values.append(memory_mb)

        stop_event.wait(0.1)

    # Take one final sample after the process has stopped.
    memory_values.append(
        get_process_tree_memory_mb(process_pid)
    )


# ==================================================
# RUN FIVE-AGENT PIPELINE WITH PERFORMANCE METRICS
# ==================================================

def run_analysis(batch_number):

    if not DATASET_FILE.exists():

        st.error("Dataset not found.")

        return

    if not PIPELINE_FILE.exists():

        st.error("Pipeline file not found.")

        return

    # Calculate how many dataset records belong to this logical batch.

    batch_start, batch_end = get_batch_range(batch_number)

    batch_record_count = max(
        0,
        batch_end - batch_start + 1
    )

    logs = []

    log_area = st.empty()

    progress_bar = st.progress(0)

    status = st.status(
        "Initializing Cyber Defense System...",
        expanded=True
    )

    agent_progress = {

        "AGENT 1:": 10,

        "AGENT 2:": 30,

        "AGENT 3:": 50,

        "AGENT 4:": 70,

        "AGENT 5:": 90

    }

    process = None

    stop_memory_monitor = threading.Event()

    memory_values = []

    memory_thread = None

    try:

        # Start the wall-clock timer immediately before launching the pipeline.

        start_time = time.perf_counter()

        process = subprocess.Popen(

            [
                sys.executable,
                "-u",
                str(PIPELINE_FILE),
                str(batch_number)
            ],

            cwd=str(DATASET_DIR),

            stdout=subprocess.PIPE,

            stderr=subprocess.STDOUT,

            text=True,

            encoding="utf-8",

            errors="replace",

            bufsize=1

        )

        st.session_state.pipeline_running = True

        # Monitor the pipeline process and its child processes.

        memory_thread = threading.Thread(

            target=monitor_peak_memory,

            args=(

                process.pid,

                stop_memory_monitor,

                memory_values

            ),

            daemon=True

        )

        memory_thread.start()

        # Read and display pipeline logs while it executes.

        for line in process.stdout:

            line = line.rstrip()

            logs.append(line)

            log_area.code(

                "\n".join(logs[-40:]),

                language="text"

            )

            for keyword, percentage in agent_progress.items():

                if keyword in line:

                    progress_bar.progress(percentage)

                    status.update(

                        label=f"Executing {keyword.rstrip(':')}..."

                    )

        return_code = process.wait()

        # Stop memory monitoring and calculate elapsed time.

        stop_memory_monitor.set()

        if memory_thread is not None:

            memory_thread.join()

        end_time = time.perf_counter()

        processing_time = end_time - start_time

        peak_memory_mb = (
            max(memory_values)
            if memory_values
            else 0.0
        )

        if processing_time > 0:

            throughput = (
                batch_record_count / processing_time
            )

        else:

            throughput = 0.0

        st.session_state.pipeline_logs = "\n".join(logs)

        st.session_state.pipeline_running = False

        if return_code == 0:

            # Store metrics inside the selected batch's result folder.

            result_folder = get_result_folder(batch_number)

            result_folder.mkdir(
                parents=True,
                exist_ok=True
            )

            performance_results = {

                "Batch Number": batch_number,

                "Dataset Records in Batch": batch_record_count,

                "Processing Time (seconds)": round(
                    processing_time,
                    3
                ),

                "Processing Throughput (records/second)": round(
                    throughput,
                    2
                ),

                "Peak Memory Usage (MB)": round(
                    peak_memory_mb,
                    2
                )

            }

            performance_file = (
                result_folder / PERFORMANCE_FILENAME
            )

            with open(
                performance_file,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    performance_results,
                    file,
                    indent=4
                )

            st.session_state.last_performance = performance_results

            progress_bar.progress(100)

            status.update(

                label="All five agents completed!",

                state="complete"

            )

            st.success(
                f"Dataset Batch {batch_number:03d} processed successfully."
            )

            st.subheader("Performance Evaluation")

            col1, col2, col3 = st.columns(3)

            col1.metric(

                "Processing Time",

                f"{processing_time:.2f} seconds"

            )

            col2.metric(

                "Throughput",

                f"{throughput:.2f} records/second"

            )

            col3.metric(

                "Peak Memory Usage",

                f"{peak_memory_mb:.2f} MB"

            )

            st.caption(
                f"Record count used for throughput: {batch_record_count:,}"
            )

            st.rerun()

        else:

            status.update(

                label="Pipeline execution failed.",

                state="error"

            )

            st.error(
                "Pipeline failed. Check the execution logs."
            )

            if st.session_state.pipeline_logs:

                st.code(

                    st.session_state.pipeline_logs,

                    language="text"

                )

    except Exception as error:

        stop_memory_monitor.set()

        if memory_thread is not None and memory_thread.is_alive():

            memory_thread.join(timeout=1)

        st.session_state.pipeline_running = False

        status.update(

            label="Execution error",

            state="error"

        )

        st.error(str(error))


# ==================================================
# LOAD SAVED PERFORMANCE METRICS
# ==================================================

def load_performance_metrics(batch_number):

    performance_file = (

        get_result_folder(batch_number) /
        PERFORMANCE_FILENAME

    )

    if not performance_file.exists():

        return None

    try:

        with open(
            performance_file,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except (OSError, json.JSONDecodeError):

        return None


# ==================================================
# SIDEBAR NAVIGATION
# ==================================================

st.sidebar.title("🛡️ CYBER DEFENSE")

st.sidebar.caption(
    "Autonomous Multi-Agent Cyber Defense System"
)

page = st.sidebar.radio(

    "NAVIGATION",

    [

        "Dashboard Overview",

        "Batch Processing",

        "Agent Results"

    ]

)

st.sidebar.divider()

st.sidebar.metric(

    "Total Dataset Records",

    f"{total_records:,}"

)

st.sidebar.metric(

    "Total Batches",

    TOTAL_BATCHES

)

# ==================================================
# MAIN HEADER
# ==================================================

st.title(
    "🛡️ AUTONOMOUS CYBER DEFENSE SYSTEM"
)

st.subheader(
    "Batch-Based Detection, Investigation and Mitigation of Potential APT Activity"
)

st.divider()

# ==================================================
# DASHBOARD OVERVIEW
# ==================================================

if page == "Dashboard Overview":

    st.header("System Overview")

    st.write(
        "Monitor the execution and results of the five autonomous cyber defense agents."
    )

    # Dataset information

    col1, col2, col3 = st.columns(3)

    col1.metric(

        "Dataset",

        "DARPA THEIA"

    )

    col2.metric(

        "Total Records",

        f"{total_records:,}"

    )

    col3.metric(

        "Processing Batches",

        "20"

    )

    st.divider()

    st.subheader("Selected Batch Results")

    selected_batch = st.selectbox(

        "Select Batch",

        range(1, TOTAL_BATCHES + 1),

        index=st.session_state.selected_batch - 1,

        format_func=lambda x: f"Dataset Batch {x:03d}"

    )

    st.session_state.selected_batch = selected_batch

    start, end = get_batch_range(selected_batch)

    col1, col2 = st.columns(2)

    col1.metric(

        "Starting Record",

        f"{start:,}"

    )

    col2.metric(

        "Ending Record",

        f"{end:,}"

    )

    st.divider()

    st.subheader("Agent Execution Status")

    for agent_name, filename in AGENTS.items():

        df = load_agent_result(

            selected_batch,

            filename

        )

        if df is None:

            st.warning(

                f"{agent_name} — Not Processed"

            )

        else:

            st.success(

                f"{agent_name} — Results Available ({len(df):,} rows)"

            )

    st.divider()

    st.info(
        "Navigate to Batch Processing to execute the five agents."
    )


# ==================================================
# BATCH PROCESSING
# ==================================================

elif page == "Batch Processing":

    st.header("Dataset Batch Processing")

    st.write(
        "Select one of the 20 logical batches of the original DARPA dataset."
    )

    st.info(

        "The original dataset is divided into 20 logical record ranges. "
        "Separate physical dataset copies are not created."

    )

    selected_batch = st.selectbox(

        "Choose Dataset Batch",

        range(1, TOTAL_BATCHES + 1),

        index=st.session_state.selected_batch - 1,

        format_func=lambda x: f"Dataset Batch {x:03d}"

    )

    st.session_state.selected_batch = selected_batch

    start, end = get_batch_range(selected_batch)

    st.divider()

    col1, col2, col3 = st.columns(3)

    col1.metric(

        "Selected Batch",

        f"{selected_batch:03d}"

    )

    col2.metric(

        "Starting Record",

        f"{start:,}"

    )

    col3.metric(

        "Ending Record",

        f"{end:,}"

    )

    st.divider()

    st.subheader("Five Autonomous Agents")

    for number, agent in enumerate(AGENTS.keys(), start=1):

        st.write(
            f"**Agent {number}:** {agent}"
        )

    st.divider()

    st.subheader("Execute Analysis")

    st.write(
        f"Run all five agents on Dataset Batch {selected_batch:03d}."
    )

    if st.button(

        "🚀 RUN ANALYSIS",

        type="primary",

        use_container_width=True

    ):

        run_analysis(selected_batch)

    st.divider()

    st.subheader("Existing Batch Results")

    result_folder = get_result_folder(selected_batch)

    if result_folder.exists():

        st.success(
            f"Results folder found: {result_folder}"
        )

    else:

        st.info(
            "This batch has not generated a results folder yet."
        )

    # Display saved performance measurements for this batch.

    st.divider()

    st.subheader("Batch Performance Metrics")

    saved_metrics = load_performance_metrics(selected_batch)

    if saved_metrics:

        metric_col1, metric_col2, metric_col3 = st.columns(3)

        metric_col1.metric(

            "Processing Time",

            f"{saved_metrics['Processing Time (seconds)']} seconds"

        )

        metric_col2.metric(

            "Throughput",

            f"{saved_metrics['Processing Throughput (records/second)']} records/sec"

        )

        metric_col3.metric(

            "Peak Memory",

            f"{saved_metrics['Peak Memory Usage (MB)']} MB"

        )

        st.write(

            f"Records assigned to this batch: "
            f"{saved_metrics['Dataset Records in Batch']:,}"

        )

        st.download_button(

            "Download Performance Metrics",

            data=json.dumps(
                saved_metrics,
                indent=4
            ),

            file_name=f"batch_{selected_batch:03d}_performance_metrics.json",

            mime="application/json"

        )

    else:

        st.info(
            "Performance metrics will appear here after you run this batch."
        )


# ==================================================
# AGENT RESULTS
# ==================================================

elif page == "Agent Results":

    st.header("Agent Analysis Results")

    selected_batch = st.selectbox(

        "Select Batch to View Results",

        range(1, TOTAL_BATCHES + 1),

        index=st.session_state.selected_batch - 1,

        format_func=lambda x: f"Dataset Batch {x:03d}"

    )

    st.session_state.selected_batch = selected_batch

    st.divider()

    for agent_name, filename in AGENTS.items():

        st.subheader(agent_name)

        df = load_agent_result(

            selected_batch,

            filename

        )

        if df is None:

            st.info(
                "No result file found. Process this batch first."
            )

        else:

            st.success(
                f"{len(df):,} result rows available."
            )

            if df.empty:

                st.info(
                    "The agent completed but produced no result rows."
                )

            else:

                st.dataframe(

                    df.head(500),

                    use_container_width=True,

                    hide_index=True

                )

                st.download_button(

                    "Download Results CSV",

                    data=df.to_csv(
                        index=False
                    ).encode("utf-8"),

                    file_name=(
                        f"batch_{selected_batch:03d}_{filename}"
                    ),

                    mime="text/csv"

                )

        st.divider()