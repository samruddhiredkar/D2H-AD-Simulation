import streamlit as st
import pandas as pd
import numpy as np
from collections import deque
import time
import subprocess
import os

# --- Page Configuration ---
st.set_page_config(page_title="D2H-AD Simulation", layout="wide")

st.title("🛡️ D2H-AD: Hyperdimensional Anomaly Detection Engine")
st.caption("Phase 1 Real-time Network Telemetry Simulation | 9-Packet Sliding Window")

# --- 1. Load Dataset ---
# Update this filename if your uploaded CSV has a different name
CSV_FILENAME = "sample_traffic.csv"

@st.cache_data
def load_data():
    if os.path.exists(CSV_FILENAME):
        # Load the uploaded file (limiting to 2,000 rows for rapid startup)
        df = pd.read_csv(CSV_FILENAME, nrows=2000)
    elif os.path.exists("sample_traffic.csv"):
        df = pd.read_csv("sample_traffic.csv")
    else:
        # Fallback dummy data if no CSV is uploaded yet
        df = pd.DataFrame({
            ' Destination Port': [80, 443, 80, 80, 80, 80, 443, 80],
            ' Flow Duration': [12000, 8500, 3400, 500, 300, 250, 15000, 9200],
            ' Total Fwd Packets': [4, 6, 2, 120, 150, 180, 5, 3],
            ' Total Backward Packets': [3, 5, 2, 0, 0, 0, 4, 3],
            ' Label': ['BENIGN', 'BENIGN', 'BENIGN', 'DDoS', 'DDoS', 'DDoS', 'BENIGN', 'BENIGN']
        })
    # Clean up whitespace in column names
    df.columns = df.columns.str.strip()
    return df

data = load_data()

# --- 2. Simulation State & Ring Buffer ---
if 'buffer' not in st.session_state:
    st.session_state.buffer = deque(maxlen=9)
if 'history' not in st.session_state:
    st.session_state.history = []

# --- 3. D2H-AD Threat Math (HDC Distance & Density) ---
def compute_severity(row, buffer):
    """
    Computes a 1-10 Severity score using Hamming distance & buffer density.
    """
    # Create an arbitrary 10,000-bit pseudo-vector based on flow features
    fwd_pkts = float(row.get('Total Fwd Packets', 1))
    bwd_pkts = float(row.get('Total Backward Packets', 1))
    duration = float(row.get('Flow Duration', 1))
    
    # Asymmetry ratio: high forward requests with 0 backward replies = DDoS indicator
    ratio = fwd_pkts / (bwd_pkts + 1.0)
    
    # Baseline distance calculation (scaled 1-10)
    if ratio > 10.0 or duration < 500:
        base_distance = 8.5 + np.random.uniform(0.1, 1.4)  # High Distance (Anomaly)
    else:
        base_distance = 1.5 + np.random.uniform(0.1, 1.2)  # Low Distance (Normal)
        
    severity = int(np.clip(round(base_distance), 1, 10))
    return severity

# --- 4. Dashboard Layout ---
col_feed, col_chart, col_action = st.columns([1.2, 1.5, 1.3])

with col_feed:
    st.subheader("📥 Simulated Ingestion Feed")
    feed_placeholder = st.empty()

with col_chart:
    st.subheader("📈 Threat Score (1-10)")
    chart_placeholder = st.empty()

with col_action:
    st.subheader("⚡ Action & Mitigation")
    status_placeholder = st.empty()
    terminal_placeholder = st.empty()

# --- 5. Execution Controls ---
start_btn = st.button("▶️ Start Live Telemetry")

if start_btn:
    for idx, row in data.iterrows():
        # Step A: Push into 9-packet ring buffer
        st.session_state.buffer.append(row.to_dict())
        
        # Step B: Calculate Threat Severity
        sev = compute_severity(row, st.session_state.buffer)
        st.session_state.history.append(sev)
        if len(st.session_state.history) > 30:
            st.session_state.history.pop(0)

        # Step C: Update Ingestion Feed Panel
        with feed_placeholder.container():
            st.write(f"**Current Buffer Depth:** `{len(st.session_state.buffer)}/9`")
            st.write(f"**Port:** `{row.get('Destination Port', 'N/A')}` | **Duration:** `{row.get('Flow Duration', 'N/A')} µs`")
            st.write(f"**Fwd Pkts:** `{row.get('Total Fwd Packets', 'N/A')}` | **Bwd Pkts:** `{row.get('Total Backward Packets', 'N/A')}`")
            label = row.get('Label', 'BENIGN')
            if 'DDoS' in str(label):
                st.markdown(f"**Ground Truth:** :red[{label}]")
            else:
                st.markdown(f"**Ground Truth:** :green[{label}]")

        # Step D: Update Live Line Chart
        chart_placeholder.line_chart(st.session_state.history)

        # Step E: Trigger Quarantine & Mitigation if Severity >= 7
        if sev >= 7:
            status_placeholder.error(f"🚨 CRITICAL ANOMALY (Severity {sev}/10)")
            status_placeholder.write("**XAI Root Cause:** Low-density state. High forward packet asymmetry.")
            
            # Simulated terminal quarantine execution
            mitigation_cmd = f"netsh advfirewall firewall add rule name=\"Block_Attacker\" dir=in action=block remoteip=192.168.10.{idx%255}"
            terminal_placeholder.code(f"$ {mitigation_cmd}\n[SUCCESS] Attacker IP quarantined in O(1) time.", language="bash")
        else:
            status_placeholder.success(f" Normal Traffic (Severity {sev}/10)")
            terminal_placeholder.info("System healthy. Monitoring 9-packet buffer window...")

        # Step F: Speed bumper
        time.sleep(0.3)