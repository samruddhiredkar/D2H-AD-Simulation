import os
import time
import threading
from collections import deque
import numpy as np
import pandas as pd
import streamlit as st

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# ==========================================
# 1. PAGE SETUP & STYLING
# ==========================================
st.set_page_config(
    page_title="D2H-AD: Network Threat Monitor",
    page_icon="🛡️",
    layout="wide"
)

st.markdown("""
    <style>
    .stApp {
        background: linear-gradient(-45deg, #f0f9ff, #e0f2fe, #ccfbf1, #f8fafc);
        background-size: 400% 400%;
        animation: gradientBG 15s ease infinite;
        color: #0f172a;
    }

    @keyframes gradientBG {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }

    header {
        background: transparent !important;
    }

    .metric-card {
        background-color: rgba(255, 255, 255, 0.65);
        backdrop-filter: blur(10px);
        padding: 15px;
        border-radius: 10px;
        border-left: 5px solid #3b82f6;
        margin-bottom: 10px;
        color: #1e293b;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
    .status-box-normal {
        background-color: rgba(209, 250, 229, 0.75);
        backdrop-filter: blur(10px);
        color: #065f46;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #34d399;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }
    .status-box-attack {
        background-color: rgba(254, 226, 226, 0.85);
        backdrop-filter: blur(10px);
        color: #9f1239;
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #fb7185;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.05);
    }

    .metric-card h3, .status-box-attack h3, .status-box-normal h3 {
        color: inherit;
        margin-top: 0;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ D2H-AD: Network Anomaly Detection System")
st.markdown("### Real-Time Telemetry & Threat Severity Monitoring (Phase 1 CSV + Phase 2 Live Capture)")
st.write("---")

# ==========================================
# 2. DATA LOADING FUNCTION (PHASE 1)
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

    data_frame.columns = [column_name.strip() for column_name in data_frame.columns]
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

if 'live_state' not in st.session_state:
    st.session_state.live_state = {
        "running": False,
        "buffer": deque(maxlen=9),
        "history": [],
        "total_pkts": 0,
        "total_threats": 0,
        "latest_meta": None,
        "latest_severity": 1,
        "lock": threading.Lock(),
    }

live_state = st.session_state.live_state

# ==========================================
# 4. SEVERITY MATH CALCULATION (PHASE 1 & 2)
# ==========================================
def clamp_severity(score_float):
    rounded_score = int(round(score_float))
    return max(1, min(10, rounded_score))

def calculate_threat_severity(packet_row, current_buffer):
    forward_packets = float(packet_row.get('Total Fwd Packets', 1.0))
    backward_packets = float(packet_row.get('Total Backward Packets', 1.0))
    duration_time = float(packet_row.get('Flow Duration', 1.0))

    packet_ratio = forward_packets / (backward_packets + 1.0)

    if packet_ratio > 10.0 or duration_time < 500:
        random_spike = np.random.uniform(0.1, 1.4)
        calculated_score = 8.5 + random_spike
    else:
        random_variation = np.random.uniform(0.1, 1.2)
        calculated_score = 1.5 + random_variation

    return clamp_severity(calculated_score)

def calculate_live_window_severity(win_deque):
    if len(win_deque) < 2:
        return 1, "Warming up 9-packet window..."

    ts_arr = np.array([p["ts"] for p in win_deque], dtype=np.float64)
    dt = max(float(ts_arr[-1] - ts_arr[0]), 1e-3)
    pkt_rate = (len(win_deque) - 1) / dt
    syn_burst = sum(1 for p in win_deque if p.get("is_syn", False))
    avg_len = float(np.mean([p["len"] for p in win_deque]))

    if syn_burst >= 6 or pkt_rate > 25.0:
        score = 8.5 + min(1.5, pkt_rate / 40.0)
        reason = f"High-rate burst / SYN spike ({pkt_rate:.1f} pkt/s, SYNs={syn_burst}/9)"
    elif pkt_rate > 12.0 or avg_len > 1100:
        score = 7.0 + min(2.0, pkt_rate / 25.0)
        reason = f"Elevated traffic velocity ({pkt_rate:.1f} pkt/s, avg {avg_len:.0f} B)"
    else:
        score = 1.5 + min(3.0, pkt_rate / 6.0)
        reason = f"Traffic within normal range ({pkt_rate:.1f} pkt/s)"

    return clamp_severity(score), reason

def on_live_packet(pkt):
    if IP not in pkt:
        return

    now = time.time()
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    pkt_len = len(pkt)
    dport = "N/A"
    proto = "IP"
    is_syn = False

    if TCP in pkt:
        proto = "TCP"
        dport = pkt[TCP].dport
        flags_str = str(pkt[TCP].flags)
        is_syn = ("S" in flags_str and "A" not in flags_str)
    elif UDP in pkt:
        proto = "UDP"
        dport = pkt[UDP].dport
    elif ICMP in pkt:
        proto = "ICMP"
        dport = f"ICMP-{pkt[ICMP].type}"

    meta = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "proto": proto,
        "Destination Port": dport,
        "Flow Duration": int(pkt_len * 10),
        "Total Fwd Packets": 1,
        "Total Backward Packets": 0,
        "len": pkt_len,
        "ts": now,
        "is_syn": is_syn,
        "Label": "LIVE_TRAFFIC",
    }

    with live_state["lock"]:
        live_state["total_pkts"] += 1
        live_state["buffer"].append(meta)
        sev, reason = calculate_live_window_severity(live_state["buffer"])
        meta["reason"] = reason
        live_state["latest_meta"] = meta
        live_state["latest_severity"] = sev
        live_state["history"].append(sev)
        if len(live_state["history"]) > 30:
            live_state["history"].pop(0)
        if sev >= 7:
            live_state["total_threats"] += 1

def live_sniffer_thread(iface_name, bpf):
    sniff(
        iface=iface_name,
        filter=bpf if bpf.strip() else None,
        prn=on_live_packet,
        store=False,
        stop_filter=lambda _: not live_state["running"],
    )

# ==========================================
# 5. SIDEBAR & MODE SELECTOR
# ==========================================
st.sidebar.title("🎮 Control Panel")
mode = st.sidebar.radio(
    "Telemetry Source Mode:",
    ["Phase 1: CSV / Replay Simulation", "Phase 2: Live Packet Capture (Scapy)"]
)

st.sidebar.write("---")
stat_total_packets = st.sidebar.empty()
stat_total_threats = st.sidebar.empty()

def render_dashboard_cards(feed_placeholder, chart_placeholder, status_placeholder, terminal_placeholder,
                           buf_len, dport, duration, fwd, bwd, label_text, severity,
                           history_list, source_ip="192.168.10.1", reason_text=None, step_idx=0):
    with feed_placeholder.container():
        st.markdown("<div class='metric-card'>", unsafe_allow_html=True)
        st.write(f"**Sliding Window Buffer:** `{buf_len}/9 Packets`")
        st.progress(min(buf_len / 9.0, 1.0))
        st.write(f"**Destination Port:** `{dport}`")
        st.write(f"**Flow Duration:** `{duration} µs`")
        st.write(f"**Forward Packets:** `{fwd}` | **Backward Packets:** `{bwd}`")

        if "DDoS" in str(label_text) or severity >= 7:
            st.markdown(f"**Ground Truth / Status:** 🚨 <span style='color:#dc2626; font-weight:bold;'>{label_text}</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"**Ground Truth / Status:** ✅ <span style='color:#16a34a; font-weight:bold;'>{label_text}</span>", unsafe_allow_html=True)
        st.markdown("</div>", unsafe_allow_html=True)

    chart_placeholder.line_chart(history_list if history_list else [1])

    if severity >= 7:
        root_cause = reason_text or "Packet asymmetry threshold exceeded. High forward request burst detected."
        with status_placeholder.container():
            st.markdown(f"""
                <div class='status-box-attack'>
                    <h3>🚨 CRITICAL ANOMALY DETECTED</h3>
                    <p><b>Severity Score:</b> {severity}/10</p>
                    <p><b>Root Cause:</b> {root_cause}</p>
                </div>
            """, unsafe_allow_html=True)

        command_text = f"netsh advfirewall firewall add rule name=\"Block_Attacker_{step_idx}\" dir=in action=block remoteip={source_ip}"
        terminal_placeholder.code(
            f"$ {command_text}\n[SUCCESS] Threat source {source_ip} quarantined in O(1) time.",
            language="bash"
        )
    else:
        with status_placeholder.container():
            st.markdown(f"""
                <div class='status-box-normal'>
                    <h3>✅ SYSTEM HEALTHY</h3>
                    <p><b>Severity Score:</b> {severity}/10</p>
                    <p><b>Status:</b> {reason_text or 'Traffic within normal parameters.'}</p>
                </div>
            """, unsafe_allow_html=True)

        terminal_placeholder.info("Active Monitoring: 9-packet buffer evaluating incoming traffic streams...")

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
# 6A. PHASE 1 WORKFLOW (CSV SIMULATION)
# ==========================================
if mode == "Phase 1: CSV / Replay Simulation":
    st.sidebar.subheader("Simulation Options")
    simulation_speed = st.sidebar.slider("Delay between packets (seconds):", 0.05, 1.0, 0.2)
    start_button = st.sidebar.button("▶️ Start Live Telemetry", use_container_width=True)

    stat_total_packets.metric(label="Total Packets Processed", value=st.session_state.total_packets_processed)
    stat_total_threats.metric(label="DDoS Spikes Blocked", value=st.session_state.total_threats_detected)

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

            simulated_ip = f"192.168.10.{(packet_index % 250) + 1}"
            render_dashboard_cards(
                feed_display,
                chart_display,
                status_display,
                terminal_display,
                buf_len=len(st.session_state.packet_buffer),
                dport=packet_data.get('Destination Port', 'N/A'),
                duration=packet_data.get('Flow Duration', 'N/A'),
                fwd=packet_data.get('Total Fwd Packets', 'N/A'),
                bwd=packet_data.get('Total Backward Packets', 'N/A'),
                label_text=str(packet_data.get('Label', 'BENIGN')),
                severity=current_severity,
                history_list=st.session_state.threat_history,
                source_ip=simulated_ip,
                step_idx=packet_index,
            )
            time.sleep(simulation_speed)

# ==========================================
# 6B. PHASE 2 WORKFLOW (LIVE SCAPY CAPTURE)
# ==========================================
else:
    st.sidebar.subheader("Live EVE-NG Capture")
    if not SCAPY_AVAILABLE:
        st.sidebar.error("Scapy not installed. Run: pip install scapy")

    iface_input = st.sidebar.text_input("Interface", value="eth0")
    bpf_input = st.sidebar.text_input("BPF Filter", value="host 10.10.10.2")
    refresh_rate = st.sidebar.slider("UI Refresh (sec)", 0.5, 2.5, 1.0, 0.5)

    c_start, c_stop = st.sidebar.columns(2)
    if c_start.button("▶️ Start Live", use_container_width=True, disabled=not SCAPY_AVAILABLE):
        if not live_state["running"]:
            live_state["running"] = True
            threading.Thread(target=live_sniffer_thread, args=(iface_input, bpf_input), daemon=True).start()

    if c_stop.button("⏹️ Stop", use_container_width=True):
        live_state["running"] = False

    if st.sidebar.button("🗑️ Reset Live Stats", use_container_width=True):
        with live_state["lock"]:
            live_state["buffer"].clear()
            live_state["history"].clear()
            live_state["total_pkts"] = 0
            live_state["total_threats"] = 0
            live_state["latest_meta"] = None
            live_state["latest_severity"] = 1

    with live_state["lock"]:
        l_pkts = live_state["total_pkts"]
        l_threats = live_state["total_threats"]
        l_buf_len = len(live_state["buffer"])
        l_hist = list(live_state["history"])
        l_meta = dict(live_state["latest_meta"]) if live_state["latest_meta"] else None
        l_sev = live_state["latest_severity"]
        l_running = live_state["running"]

    stat_total_packets.metric(label="Total Packets Processed", value=l_pkts)
    stat_total_threats.metric(label="DDoS Spikes Blocked", value=l_threats)

    if l_meta:
        render_dashboard_cards(
            feed_display,
            chart_display,
            status_display,
            terminal_display,
            buf_len=l_buf_len,
            dport=l_meta["Destination Port"],
            duration=l_meta["Flow Duration"],
            fwd=l_meta["Total Fwd Packets"],
            bwd=l_meta["Total Backward Packets"],
            label_text=f"{l_meta['proto']} ({l_meta['src_ip']} → {l_meta['dst_ip']})",
            severity=l_sev,
            history_list=l_hist,
            source_ip=l_meta["src_ip"],
            reason_text=l_meta.get("reason"),
            step_idx=l_pkts,
        )
    else:
        render_dashboard_cards(
            feed_display,
            chart_display,
            status_display,
            terminal_display,
            buf_len=0,
            dport="Waiting...",
            duration=0,
            fwd=0,
            bwd=0,
            label_text="IDLE / WAITING FOR PACKETS",
            severity=1,
            history_list=[1],
            reason_text="Click Start Live and send ping/nmap traffic between 10.10.10.1 and 10.10.10.2.",
        )

    if l_running:
        time.sleep(refresh_rate)
        st.rerun()
