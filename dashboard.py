import streamlit as st
import pandas as pd
import subprocess
import sys
from pathlib import Path
import math

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
# RUN FIVE-AGENT PIPELINE
# ==================================================

def run_analysis(batch_number):

    if not DATASET_FILE.exists():

        st.error("Dataset not found.")

        return

    if not PIPELINE_FILE.exists():

        st.error("Pipeline file not found.")

        return

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

    try:

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

        for line in process.stdout:

            line = line.rstrip()

            logs.append(line)

            log_area.code(
                "\n".join(logs[-40:]),
                language="text"
            )

            for keyword, percentage in agent_progress.items():

                if keyword in line:

                    progress_bar.progress(
                        percentage
                    )

                    status.update(
                        label=f"Executing {keyword.rstrip(':')}..."
                    )

        return_code = process.wait()

        st.session_state.pipeline_logs = "\n".join(logs)

        st.session_state.pipeline_running = False

        if return_code == 0:

            progress_bar.progress(100)

            status.update(
                label="All five agents completed!",
                state="complete"
            )

            st.success(
                f"Dataset Batch {batch_number:03d} processed successfully."
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

    except Exception as error:

        st.session_state.pipeline_running = False

        status.update(
            label="Execution error",
            state="error"
        )

        st.error(str(error))


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
    "Real-Time Detection, Investigation and Mitigation of APT Attacks"
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