import streamlit as st
import pandas as pd
import numpy as np
from collections import deque
import time
import os

# ==========================================
# 1. PAGE SETUP & STYLING
# ==========================================
st.set_page_config(
    page_title="D2H-AD: Network Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS styling with ANIMATED BACKGROUND and Frosted Glass Cards
st.markdown("""
    <style>
    /* 1. The Soothing Animated Background */
    .stApp {
        background: linear-gradient(-45deg, #0f172a, #172554, #064e3b, #1e1b4b);
        background-size: 400% 400%;
        animation: gradientBG 15s ease infinite;
    }

    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* Make Streamlit's default top header transparent so it doesn't block the animation */
    header {
        background: transparent !important;
    }

    /* 2. Frosted Glass Effect (Glassmorphism) for the cards */
    .metric-card {
        background-color: rgba(30, 41, 59, 0.75); /* Semi-transparent */
        backdrop-filter: blur(10px); /* Blurs the moving background behind it */
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 10px;
    }
    .status-box-normal {
        background-color: rgba(6, 78, 59, 0.75);
        backdrop-filter: blur(10px);
        color: #6ee7b7;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #059669;
    }
    .status-box-attack {
        background-color: rgba(136, 19, 55, 0.85);
        backdrop-filter: blur(10px);
        color: #fca5a5;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #e11d48;
    }
    </style>
""", unsafe_allow_html=True)

# Main Title and Subtitle
st.title("🛡️ D2H-AD: Network Anomaly Detection System")
st.markdown("### Real-Time Telemetry & Threat Severity Monitoring")
st.write("---")

# ==========================================
# 2. DATA LOADING FUNCTION
# ==========================================
# We load our lightweight network dataset into memory
dataset_path = "sample_traffic.csv"

@st.cache_data
def load_network_dataset():
    # Check if our sample file exists in the folder
    if os.path.exists(dataset_path):
        data_frame = pd.read_csv(dataset_path)
    else:
        # Fallback dummy data if sample_traffic.csv is missing
        backup_data = {
            'Destination Port': [80, 443, 80, 80, 80, 80, 443, 80],
            'Flow Duration': [12000, 8500, 3400, 500, 300, 250, 15000, 9200],
            'Total Fwd Packets': [4, 6, 2, 120, 150, 180, 5, 3],
            'Total Backward Packets': [3, 5, 2, 0, 0, 0, 4, 3],
            'Label': ['BENIGN', 'BENIGN', 'BENIGN', 'DDoS', 'DDoS', 'DDoS', 'BENIGN', 'BENIGN']
        }
        data_frame = pd.DataFrame(backup_data)
    
    # Strip extra spaces from column headers
    cleaned_columns = []
    for column_name in data_frame.columns:
        cleaned_columns.append(column_name.strip())
    data_frame.columns = cleaned_columns
    
    return data_frame

# Load the dataset
network_data = load_network_dataset()

# ==========================================
# 3. INITIALIZE SESSION STATE
# ==========================================
# Session state stores our ring buffer and history so Streamlit doesn't reset them
if 'packet_buffer' not in st.session_state:
    st.session_state.packet_buffer = deque(maxlen=9)

if 'threat_history' not in st.session_state:
    st.session_state.threat_history = []

if 'total_packets_processed' not in st.session_state:
    st.session_state.total_packets_processed = 0

if 'total_threats_detected' not in st.session_state:
    st.session_state.total_threats_detected = 0

# ==========================================
# 4. SEVERITY MATH CALCULATION
# ==========================================
def calculate_threat_severity(packet_row, current_buffer):
    """
    Calculates a severity score from 1 to 10 based on packet asymmetry 
    and flow duration.
    """
    # Extract feature values safely with default fallbacks
    if 'Total Fwd Packets' in packet_row:
        forward_packets = float(packet_row['Total Fwd Packets'])
    else:
        forward_packets = 1.0

    if 'Total Backward Packets' in packet_row:
        backward_packets = float(packet_row['Total Backward Packets'])
    else:
        backward_packets = 1.0

    if 'Flow Duration' in packet_row:
        duration_time = float(packet_row['Flow Duration'])
    else:
        duration_time = 1.0

    # Calculate packet ratio (forward vs backward)
    # High forward packets with zero or low backward packets indicates a flood attack
    packet_ratio = forward_packets / (backward_packets + 1.0)

    # Determine base threat score
    if packet_ratio > 10.0 or duration_time < 500:
        # High likelihood of attack
        random_spike = np.random.uniform(0.1, 1.4)
        calculated_score = 8.5 + random_spike
    else:
        # Normal traffic pattern
        random_variation = np.random.uniform(0.1, 1.2)
        calculated_score = 1.5 + random_variation

    # Round the final score and clip it between 1 and 10
    rounded_score = int(round(calculated_score))
    
    if rounded_score > 10:
        final_severity = 10
    elif rounded_score < 1:
        final_severity = 1
    else:
        final_severity = rounded_score

    return final_severity

# ==========================================
# 5. SIDEBAR & STATS PANEL
# ==========================================
st.sidebar.title("🎮 Control Panel")
st.sidebar.subheader("Simulation Options")

simulation_speed = st.sidebar.slider("Delay between packets (seconds):", 0.05, 1.0, 0.2)
start_button = st.sidebar.button("▶️ Start Live Telemetry", use_container_width=True)

st.sidebar.write("---")
st.sidebar.subheader("📊 Session Statistics")
stat_total_packets = st.sidebar.empty()
stat_total_threats = st.sidebar.empty()

stat_total_packets.metric(label="Total Packets Processed", value=st.session_state.total_packets_processed)
stat_total_threats.metric(label="DDoS Spikes Blocked", value=st.session_state.total_threats_detected)

# ==========================================
# 6. DASHBOARD LAYOUT COLUMNS
# ==========================================
column_feed, column_chart, column_action = st.columns([1.2, 1.8, 1.4])

with column_feed:
    st.subheader("📥 Incoming Telemetry")
    feed_display = st.empty()

with column_chart:
    st.subheader("📈 Live Threat Score (1-10 Scale)")
    chart_display = st.empty()

with column_action:
    st.subheader("⚡ Automated Mitigation")
    status_display = st.empty()
    terminal_display = st.empty()

# ==========================================
# 7. MAIN SIMULATION LOOP
# ==========================================
if start_button:
    # Reset history on new run
    st.session_state.threat_history = []
    st.session_state.total_packets_processed = 0
    st.session_state.total_threats_detected = 0

    # Iterate row by row through the network dataset
    for packet_index, packet_data in network_data.iterrows():
        
        # Step 1: Update buffer and packet counters
        st.session_state.packet_buffer.append(packet_data.to_dict())
        st.session_state.total_packets_processed += 1
        
        # Step 2: Compute threat score
        current_severity = calculate_threat_severity(packet_data, st.session_state.packet_buffer)
        st.session_state.threat_history.append(current_severity)
        
        # Keep chart history limited to the last 30 readings
        if len(st.session_state.threat_history) > 30:
            st.session_state.threat_history.pop(0)

        # Count detected threats
        if current_severity >= 7:
            st.session_state.total_threats_detected += 1

        # Update sidebar metrics live
        stat_total_packets.metric(label="Total Packets Processed", value=st.session_state.total_packets_processed)
        stat_total_threats.metric(label="DDoS Spikes Blocked", value=st.session_state.total_threats_detected)

        # Step 3: Render Ingestion Feed Card
        with feed_display.container():
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            
            # Show buffer filling up
            buffer_depth = len(st.session_state.packet_buffer)
            st.write(f"**Sliding Window Buffer:** `{buffer_depth}/9 Packets`")
            st.progress(buffer_depth / 9.0)
            
            # Extract packet fields
            dest_port = packet_data.get('Destination Port', 'N/A')
            flow_duration = packet_data.get('Flow Duration', 'N/A')
            fwd_pkts = packet_data.get('Total Fwd Packets', 'N/A')
            bwd_pkts = packet_data.get('Total Backward Packets', 'N/A')
            ground_truth = str(packet_data.get('Label', 'BENIGN'))

            st.write(f"**Destination Port:** `{dest_port}`")
            st.write(f"**Flow Duration:** `{flow_duration} µs`")
            st.write(f"**Forward Packets:** `{fwd_pkts}` | **Backward Packets:** `{bwd_pkts}`")
            
            if "DDoS" in ground_truth:
                st.markdown(f"**Ground Truth Label:** 🚨 <span style='color:#f87171; font-weight:bold;'>{ground_truth}</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"**Ground Truth Label:** ✅ <span style='color:#4ade80; font-weight:bold;'>{ground_truth}</span>", unsafe_allow_html=True)
                
            st.markdown("</div>", unsafe_allow_html=True)

        # Step 4: Render Live Threat Line Chart
        chart_display.line_chart(st.session_state.threat_history)

        # Step 5: Render Action & Mitigation Card
        if current_severity >= 7:
            with status_display.container():
                st.markdown(f"""
                    <div class='status-box-attack'>
                        <h3>🚨 CRITICAL ANOMALY DETECTED</h3>
                        <p><b>Severity Score:</b> {current_severity}/10</p>
                        <p><b>Root Cause:</b> Packet asymmetry threshold exceeded. High forward request burst detected.</p>
                    </div>
                """, unsafe_allow_html=True)
            
            # Simulated Firewall IP Block Command
            simulated_ip = f"192.168.10.{(packet_index % 250) + 1}"
            command_text = f"netsh advfirewall firewall add rule name=\"Block_Attacker_{packet_index}\" dir=in action=block remoteip={simulated_ip}"
            
            terminal_display.code(
                f"$ {command_text}\n[SUCCESS] Threat source {simulated_ip} quarantined in O(1) time.", 
                language="bash"
            )
        else:
            with status_display.container():
                st.markdown(f"""
                    <div class='status-box-normal'>
                        <h3>✅ SYSTEM HEALTHY</h3>
                        <p><b>Severity Score:</b> {current_severity}/10</p>
                        <p><b>Status:</b> Traffic within normal parameters.</p>
                    </div>
                """, unsafe_allow_html=True)
            
            terminal_display.info("Active Monitoring: 9-packet buffer evaluating incoming traffic streams...")

        # Step 6: Delay loop iteration
        time.sleep(simulation_speed)
