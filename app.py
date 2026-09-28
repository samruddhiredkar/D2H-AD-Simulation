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

# Custom CSS styling with LIGHT ANIMATED BACKGROUND and Soft Frosted Glass Cards
st.markdown("""
    <style>
    /* 1. The Soothing Light Animated Background */
    .stApp {
        background: linear-gradient(-45deg, #f0f9ff, #e0f2fe, #ccfbf1, #f8fafc);
        background-size: 400% 400%;
        animation: gradientBG 15s ease infinite;
        color: #0f172a; /* Dark default text */
    }

    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    /* Make Streamlit's default top header transparent */
    header {
        background: transparent !important;
    }

    /* 2. Light Frosted Glass Effect (Glassmorphism) */
    .metric-card {
        background-color: rgba(255, 255, 255, 0.65); /* Semi-transparent white */
        backdrop-filter: blur(10px);
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 10px;
        color: #1e293b;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05); /* Soft shadow for depth */
    }
    .status-box-normal {
        background-color: rgba(209, 250, 229, 0.75); /* Soft mint */
        backdrop-filter: blur(10px);
        color: #065f46; /* Dark green text */
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #34d399;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
    .status-box-attack {
        background-color: rgba(254, 226, 226, 0.85); /* Soft pink/red */
        backdrop-filter: blur(10px);
        color: #9f1239; /* Dark red text */
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #fb7185;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
    
    /* Ensure all markdown headings in the cards stay dark */
    .metric-card h3, .status-box-attack h3, .status-box-normal h3 {
        color: inherit;
        margin-top: 0;
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
dataset_path = "sample_traffic.csv"

@st.cache_data
def load_network_dataset():
    if os.path.exists(dataset_path):
        data_frame = pd.read_csv(dataset_path)
    else:
        backup_data = {
            'Destination Port': [80, 443, 80, 80, 80, 80, 443, 80],
            'Flow Duration': [12000, 8500, 3400, 500, 300, 250, 15000, 9200],
            'Total Fwd Packets': [4, 6, 2, 120, 150, 180, 5, 3],
            'Total Backward Packets': [3, 5, 2, 0, 0, 0, 4, 3],
            'Label': ['BENIGN', 'BENIGN', 'BENIGN', 'DDoS', 'DDoS', 'DDoS', 'BENIGN', 'BENIGN']
        }
        data_frame = pd.DataFrame(backup_data)
    
    cleaned_columns = []
    for column_name in data_frame.columns:
        cleaned_columns.append(column_name.strip())
    data_frame.columns = cleaned_columns
    
    return data_frame

network_data = load_network_dataset()

# ==========================================
# 3. INITIALIZE SESSION STATE
# ==========================================
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

    packet_ratio = forward_packets / (backward_packets + 1.0)

    if packet_ratio > 10.0 or duration_time < 500:
        random_spike = np.random.uniform(0.1, 1.4)
        calculated_score = 8.5 + random_spike
    else:
        random_variation = np.random.uniform(0.1, 1.2)
        calculated_score = 1.5 + random_variation

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
    st.session_state.threat_history = []
    st.session_state.total_packets_processed = 0
    st.session_state.total_threats_detected = 0

    for packet_index, packet_data in network_data.iterrows():
        
        st.session_state.packet_buffer.append(packet_data.to_dict())
        st.session_state.total_packets_processed += 1
        
        current_severity = calculate_threat_severity(packet_data, st.session_state.packet_buffer)
        st.session_state.threat_history.append(current_severity)
        
        if len(st.session_state.threat_history) > 30:
            st.session_state.threat_history.pop(0)

        if current_severity >= 7:
            st.session_state.total_threats_detected += 1

        stat_total_packets.metric(label="Total Packets Processed", value=st.session_state.total_packets_processed)
        stat_total_threats.metric(label="DDoS Spikes Blocked", value=st.session_state.total_threats_detected)

        # Render Ingestion Feed Card
        with feed_display.container():
            st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
            
            buffer_depth = len(st.session_state.packet_buffer)
            st.write(f"**Sliding Window Buffer:** `{buffer_depth}/9 Packets`")
            st.progress(buffer_depth / 9.0)
            
            dest_port = packet_data.get('Destination Port', 'N/A')
            flow_duration = packet_data.get('Flow Duration', 'N/A')
            fwd_pkts = packet_data.get('Total Fwd Packets', 'N/A')
            bwd_pkts = packet_data.get('Total Backward Packets', 'N/A')
            ground_truth = str(packet_data.get('Label', 'BENIGN'))

            st.write(f"**Destination Port:** `{dest_port}`")
            st.write(f"**Flow Duration:** `{flow_duration} µs`")
            st.write(f"**Forward Packets:** `{fwd_pkts}` | **Backward Packets:** `{bwd_pkts}`")
            
            # Using darker text colors so it's readable on the light background
            if "DDoS" in ground_truth:
                st.markdown(f"**Ground Truth Label:** 🚨 <span style='color:#dc2626; font-weight:bold;'>{ground_truth}</span>", unsafe_allow_html=True)
            else:
                st.markdown(f"**Ground Truth Label:** ✅ <span style='color:#16a34a; font-weight:bold;'>{ground_truth}</span>", unsafe_allow_html=True)
                
            st.markdown("</div>", unsafe_allow_html=True)

        # Render Live Threat Line Chart
        chart_display.line_chart(st.session_state.threat_history)

        # Render Action & Mitigation Card
        if current_severity >= 7:
            with status_display.container():
                st.markdown(f"""
                    <div class='status-box-attack'>
                        <h3>🚨 CRITICAL ANOMALY DETECTED</h3>
                        <p><b>Severity Score:</b> {current_severity}/10</p>
                        <p><b>Root Cause:</b> Packet asymmetry threshold exceeded. High forward request burst detected.</p>
                    </div>
                """, unsafe_allow_html=True)
            
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

        time.sleep(simulation_speed)
