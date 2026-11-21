import base64, json, time, urllib.request
from collections import deque
from scapy.all import sniff, IP, TCP, ICMP

REPO = "samruddhiredkar/D2H-AD-Simulation"
PATH = "live_telemetry.json"
TOKEN = "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"

win = deque(maxlen=9)
history = [1]
total_pkts = 0
total_threats = 0
last_push = 0.0

def push_to_github(payload):
    api_url = f"https://api.github.com/repos/{REPO}/contents/{PATH}"
    headers = {
        "Authorization": f"Bearer {TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "nids-bridge",
    }
    sha = None
    try:
        with urllib.request.urlopen(urllib.request.Request(api_url, headers=headers), timeout=5) as r:
            sha = json.loads(r.read().decode()).get("sha")
    except Exception:
        pass
    body = {
        "message": "Update live EVE-NG telemetry",
        "content": base64.b64encode(json.dumps(payload).encode()).decode(),
    }
    if sha:
        body["sha"] = sha
    req = urllib.request.Request(api_url, data=json.dumps(body).encode(), headers=headers, method="PUT")
    urllib.request.urlopen(req, timeout=6)

def handle_pkt(pkt):
    global total_pkts, total_threats, last_push
    if IP not in pkt:
        return
    now = time.time()
    proto = "TCP" if TCP in pkt else ("ICMP" if ICMP in pkt else "IP")
    dport = pkt[TCP].dport if TCP in pkt else (f"ICMP-{pkt[ICMP].type}" if ICMP in pkt else "N/A")
    is_syn = bool(TCP in pkt and "S" in str(pkt[TCP].flags) and "A" not in str(pkt[TCP].flags))

    win.append({"ts": now, "len": len(pkt), "is_syn": is_syn})
    total_pkts += 1

    dt = max(now - win[0]["ts"], 1e-3) if len(win) > 1 else 1.0
    rate = (len(win) - 1) / dt if len(win) > 1 else 0.0
    syn_cnt = sum(1 for x in win if x["is_syn"])
    sev = 9 if (syn_cnt >= 6 or rate > 25) else (7 if rate > 12 else min(4, max(1, int(round(1.5 + rate / 5)))))
    if sev >= 7:
        total_threats += 1

    history.append(sev)
    history[:] = history[-30:]

    if now - last_push >= 1.5:
        last_push = now
        payload = {
            "updated_at": now,
            "total_pkts": total_pkts,
            "total_threats": total_threats,
            "window_len": len(win),
            "severity": sev,
            "history": history,
            "latest": {
                "src_ip": pkt[IP].src,
                "dst_ip": pkt[IP].dst,
                "proto": proto,
                "Destination Port": dport,
                "Flow Duration": len(pkt) * 10,
                "Total Fwd Packets": 1,
                "Total Backward Packets": 0,
                "Label": f"{proto} ({pkt[IP].src} -> {pkt[IP].dst})",
                "reason": f"Live rate {rate:.1f} pkt/s, SYNs={syn_cnt}/9",
            },
        }
        try:
            push_to_github(payload)
            print(f"Sent pkt #{total_pkts} | sev={sev}")
        except Exception as e:
            print("Push retry:", e)

sniff(iface="eth0", filter="host 10.10.10.2", prn=handle_pkt, store=False)
