"""
Network Traffic Monitor + Intrusion Detection System
Uses Scapy for packet capture and rule-based threat detection.
In demo mode (no root), generates realistic simulated traffic.
"""

import threading
import time
import random
import ipaddress
from datetime import datetime
from collections import defaultdict

# Try importing scapy (requires root for live capture)
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

# ─── Shared state (thread-safe via lock) ────────────────────────────────────
_lock = threading.Lock()
_traffic_log = []          # list of packet dicts
_alerts = []               # list of alert dicts
_stats = {
    "total_packets": 0,
    "tcp": 0, "udp": 0, "icmp": 0, "other": 0,
    "bytes_total": 0,
}

# IDS tracking
_port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": None})
_dos_tracker = defaultdict(lambda: {"count": 0, "window_start": None})
_brute_force_tracker = defaultdict(lambda: {"attempts": 0, "window_start": None})

BRUTE_FORCE_PORTS = {21, 22, 23, 25, 110, 143, 3306, 5432, 3389}
PORT_SCAN_THRESHOLD = 10       # distinct ports in 5s
DOS_THRESHOLD = 100            # packets in 2s
BRUTE_FORCE_THRESHOLD = 6      # attempts in 10s


def _now():
    return datetime.now().strftime("%H:%M:%S")


def _add_alert(level, title, detail, src_ip=""):
    with _lock:
        alert = {
            "id": len(_alerts) + 1,
            "time": _now(),
            "level": level,          # critical / warning / info
            "title": title,
            "detail": detail,
            "src_ip": src_ip,
        }
        _alerts.append(alert)
        # keep last 200
        if len(_alerts) > 200:
            _alerts.pop(0)
    return alert


def _add_packet(pkt_dict):
    with _lock:
        _traffic_log.append(pkt_dict)
        if len(_traffic_log) > 500:
            _traffic_log.pop(0)
        _stats["total_packets"] += 1
        proto = pkt_dict.get("proto", "other").lower()
        if proto in _stats:
            _stats[proto] += 1
        else:
            _stats["other"] += 1
        _stats["bytes_total"] += pkt_dict.get("size", 0)


# ─── IDS Rules ───────────────────────────────────────────────────────────────

def _check_port_scan(src_ip, dst_port):
    now = time.time()
    tracker = _port_scan_tracker[src_ip]
    if tracker["first_seen"] is None or now - tracker["first_seen"] > 5:
        tracker["ports"] = set()
        tracker["first_seen"] = now
    tracker["ports"].add(dst_port)
    if len(tracker["ports"]) >= PORT_SCAN_THRESHOLD:
        tracker["ports"] = set()
        tracker["first_seen"] = now
        return _add_alert("critical", "Port Scan Detected",
                          f"Scanned {PORT_SCAN_THRESHOLD}+ ports in 5s", src_ip)
    return None


def _check_dos(src_ip):
    now = time.time()
    tracker = _dos_tracker[src_ip]
    if tracker["window_start"] is None or now - tracker["window_start"] > 2:
        tracker["count"] = 0
        tracker["window_start"] = now
    tracker["count"] += 1
    if tracker["count"] >= DOS_THRESHOLD:
        tracker["count"] = 0
        tracker["window_start"] = now
        return _add_alert("critical", "DoS Attack Detected",
                          f"{DOS_THRESHOLD}+ packets in 2s window", src_ip)
    return None


def _check_brute_force(src_ip, dst_port):
    if dst_port not in BRUTE_FORCE_PORTS:
        return None
    now = time.time()
    tracker = _brute_force_tracker[src_ip]
    if tracker["window_start"] is None or now - tracker["window_start"] > 10:
        tracker["attempts"] = 0
        tracker["window_start"] = now
    tracker["attempts"] += 1
    if tracker["attempts"] >= BRUTE_FORCE_THRESHOLD:
        tracker["attempts"] = 0
        tracker["window_start"] = now
        service = {22: "SSH", 21: "FTP", 3389: "RDP", 3306: "MySQL",
                   5432: "PostgreSQL", 23: "Telnet"}.get(dst_port, str(dst_port))
        return _add_alert("warning", f"Brute Force on {service}",
                          f"{BRUTE_FORCE_THRESHOLD}+ attempts in 10s", src_ip)
    return None


# ─── Packet processor ────────────────────────────────────────────────────────

def _process_packet(pkt):
    """Called for each real packet from Scapy."""
    if not pkt.haslayer(IP):
        return
    ip = pkt[IP]
    src, dst = ip.src, ip.dst
    proto, sport, dport, size = "other", 0, 0, len(pkt)

    if pkt.haslayer(TCP):
        proto = "TCP"
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif pkt.haslayer(UDP):
        proto = "UDP"
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    pkt_dict = {
        "time": _now(), "src": src, "dst": dst,
        "proto": proto, "sport": sport, "dport": dport, "size": size,
    }
    _add_packet(pkt_dict)
    _check_port_scan(src, dport)
    _check_dos(src)
    _check_brute_force(src, dport)


# ─── Demo mode: simulated traffic ────────────────────────────────────────────

_INTERNAL_IPS = ["192.168.1." + str(i) for i in range(2, 20)]
_EXTERNAL_IPS = ["45.33.32.156", "198.41.0.4", "8.8.8.8", "1.1.1.1",
                 "104.21.14.93", "172.67.68.142", "185.220.101.45"]
_COMMON_PORTS = [80, 443, 53, 22, 25, 110, 3306, 8080, 8443]

_ATTACK_SCENARIOS = [
    "port_scan",
    "dos_flood",
    "brute_force_ssh",
    "normal",
    "normal",
    "normal",
    "normal",
]


def _simulate_traffic():
    """Generate realistic fake traffic + periodic attack simulations."""
    scenario_counter = 0
    while True:
        scenario = random.choice(_ATTACK_SCENARIOS)
        src = random.choice(_EXTERNAL_IPS + _INTERNAL_IPS)

        if scenario == "port_scan":
            # Rapid port scan burst
            victim = random.choice(_INTERNAL_IPS)
            for port in random.sample(range(1, 1024), PORT_SCAN_THRESHOLD + 2):
                pkt = {
                    "time": _now(), "src": src, "dst": victim,
                    "proto": "TCP", "sport": random.randint(40000, 60000),
                    "dport": port, "size": random.randint(40, 80),
                }
                _add_packet(pkt)
                _check_port_scan(src, port)
                time.sleep(0.05)

        elif scenario == "dos_flood":
            victim = random.choice(_INTERNAL_IPS)
            for _ in range(DOS_THRESHOLD + 10):
                pkt = {
                    "time": _now(), "src": src, "dst": victim,
                    "proto": "ICMP", "sport": 0, "dport": 0,
                    "size": random.randint(64, 1500),
                }
                _add_packet(pkt)
                _check_dos(src)
                time.sleep(0.01)

        elif scenario == "brute_force_ssh":
            victim = random.choice(_INTERNAL_IPS)
            for _ in range(BRUTE_FORCE_THRESHOLD + 2):
                pkt = {
                    "time": _now(), "src": src, "dst": victim,
                    "proto": "TCP", "sport": random.randint(40000, 60000),
                    "dport": 22, "size": random.randint(80, 120),
                }
                _add_packet(pkt)
                _check_brute_force(src, 22)
                time.sleep(0.3)

        else:
            # Normal traffic
            dst = random.choice(_INTERNAL_IPS + _EXTERNAL_IPS)
            proto = random.choices(["TCP", "UDP", "ICMP"], weights=[6, 3, 1])[0]
            dport = random.choice(_COMMON_PORTS) if proto == "TCP" else random.randint(1, 65535)
            pkt = {
                "time": _now(), "src": src, "dst": dst,
                "proto": proto, "sport": random.randint(10000, 60000),
                "dport": dport, "size": random.randint(40, 1500),
            }
            _add_packet(pkt)

        scenario_counter += 1
        time.sleep(random.uniform(0.2, 1.2))


# ─── Public API ──────────────────────────────────────────────────────────────

_monitor_thread = None
_running = False


def start_monitor(demo_mode=True):
    global _monitor_thread, _running
    if _running:
        return
    _running = True
    if demo_mode or not SCAPY_AVAILABLE:
        t = threading.Thread(target=_simulate_traffic, daemon=True)
    else:
        def _live_sniff():
            sniff(prn=_process_packet, store=False)
        t = threading.Thread(target=_live_sniff, daemon=True)
    _monitor_thread = t
    t.start()


def get_recent_packets(n=50):
    with _lock:
        return list(_traffic_log[-n:])


def get_recent_alerts(n=30):
    with _lock:
        return list(_alerts[-n:])


def get_stats():
    with _lock:
        return dict(_stats)


def inject_attack(attack_type):
    """Manually trigger an attack simulation for demo purposes."""
    src = random.choice(_EXTERNAL_IPS)
    victim = random.choice(_INTERNAL_IPS)
    if attack_type == "port_scan":
        for port in random.sample(range(1, 1024), PORT_SCAN_THRESHOLD + 3):
            pkt = {"time": _now(), "src": src, "dst": victim, "proto": "TCP",
                   "sport": 54321, "dport": port, "size": 60}
            _add_packet(pkt)
            _check_port_scan(src, port)
    elif attack_type == "dos":
        for _ in range(DOS_THRESHOLD + 20):
            pkt = {"time": _now(), "src": src, "dst": victim, "proto": "ICMP",
                   "sport": 0, "dport": 0, "size": 1024}
            _add_packet(pkt)
            _check_dos(src)
    elif attack_type == "brute_force":
        for _ in range(BRUTE_FORCE_THRESHOLD + 3):
            pkt = {"time": _now(), "src": src, "dst": victim, "proto": "TCP",
                   "sport": 55000, "dport": 22, "size": 100}
            _add_packet(pkt)
            _check_brute_force(src, 22)
    return {"status": "injected", "type": attack_type, "src": src, "dst": victim}
