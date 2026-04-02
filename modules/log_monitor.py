"""
Log Monitoring & Alert System
Collects system/network events, detects anomalies via rule-based thresholds.
"""

import os
import time
import threading
import random
from datetime import datetime
from pathlib import Path
from collections import defaultdict

LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "soc_events.log"

_lock = threading.Lock()
_log_entries = []

ANOMALY_RULES = {
    "HIGH_LOGIN_FAILURES": {"threshold": 5, "window": 60, "severity": "critical"},
    "RAPID_REQUESTS": {"threshold": 50, "window": 10, "severity": "warning"},
    "LARGE_UPLOAD": {"threshold": 10 * 1024 * 1024, "severity": "info"},   # 10MB
    "PRIVILEGED_CMD": {"severity": "warning"},
    "NEW_PROCESS": {"severity": "info"},
}

_counters = defaultdict(lambda: {"count": 0, "window_start": None})

EVENT_TYPES = [
    "LOGIN_SUCCESS", "LOGIN_FAILURE", "FILE_ACCESS", "NETWORK_CONN",
    "PROCESS_START", "PRIVILEGE_ESCALATION", "CONFIG_CHANGE",
    "FIREWALL_BLOCK", "DNS_QUERY", "HTTP_REQUEST",
]

_USERS = ["admin", "root", "john", "alice", "system", "guest", "service"]
_SERVICES = ["sshd", "apache2", "nginx", "mysql", "vsftpd", "cron", "systemd"]


def _write_log(entry):
    with open(LOG_FILE, "a") as f:
        f.write(
            f"[{entry['time']}] {entry['level'].upper()} "
            f"{entry['event_type']} | {entry['message']}\n"
        )


def _add_log(event_type, message, level="info", user="", service="", extra=None):
    with _lock:
        entry = {
            "id": len(_log_entries) + 1,
            "time": datetime.now().strftime("%H:%M:%S"),
            "event_type": event_type,
            "level": level,
            "message": message,
            "user": user,
            "service": service,
            "extra": extra or {},
        }
        _log_entries.append(entry)
        if len(_log_entries) > 1000:
            _log_entries.pop(0)
        _write_log(entry)
    return entry


def _check_threshold(key, window_secs, threshold):
    now = time.time()
    c = _counters[key]
    if c["window_start"] is None or now - c["window_start"] > window_secs:
        c["count"] = 0
        c["window_start"] = now
    c["count"] += 1
    return c["count"] >= threshold


# ─── Simulated system events ─────────────────────────────────────────────────

def _simulate_logs():
    while True:
        event = random.choice(EVENT_TYPES)
        user = random.choice(_USERS)
        service = random.choice(_SERVICES)

        if event == "LOGIN_FAILURE":
            ip = f"192.168.1.{random.randint(2, 254)}"
            _add_log(event, f"Failed login for '{user}' from {ip}", "warning",
                     user=user, service=service, extra={"ip": ip})
            if _check_threshold(f"login_fail_{ip}", 60, 5):
                _add_log("HIGH_LOGIN_FAILURES",
                         f"[ANOMALY] 5+ login failures from {ip} in 60s",
                         "critical", user=user, extra={"ip": ip})

        elif event == "PRIVILEGE_ESCALATION":
            _add_log(event,
                     f"User '{user}' executed 'sudo' command",
                     "warning", user=user, service=service)

        elif event == "CONFIG_CHANGE":
            files = ["/etc/passwd", "/etc/sudoers", "/etc/ssh/sshd_config",
                     "/etc/hosts", "/var/www/html/config.php"]
            f = random.choice(files)
            _add_log(event, f"Config file modified: {f}",
                     "warning", user=user, service=service, extra={"file": f})

        elif event == "FIREWALL_BLOCK":
            src = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            port = random.choice([22, 23, 3389, 445, 1433, 3306])
            _add_log(event, f"Blocked inbound {src}:{port}",
                     "info", service="iptables", extra={"src": src, "port": port})

        elif event == "LOGIN_SUCCESS":
            _add_log(event, f"User '{user}' authenticated via {service}",
                     "info", user=user, service=service)

        elif event == "HTTP_REQUEST":
            codes = [200, 200, 200, 301, 403, 404, 500]
            code = random.choice(codes)
            paths = ["/", "/admin", "/login", "/api/v1/users", "/.env", "/wp-admin"]
            path = random.choice(paths)
            level = "warning" if code in (403, 500) or path in ("/.env", "/wp-admin") else "info"
            _add_log(event, f"HTTP {code} {path}", level, service="webserver",
                     extra={"code": code, "path": path})

        else:
            _add_log(event,
                     f"{service} event: {event.replace('_', ' ').lower()}",
                     "info", user=user, service=service)

        time.sleep(random.uniform(0.5, 2.5))


_sim_thread = None
_running = False


def start_log_monitor():
    global _sim_thread, _running
    if _running:
        return
    _running = True
    t = threading.Thread(target=_simulate_logs, daemon=True)
    _sim_thread = t
    t.start()


def get_recent_logs(n=100):
    with _lock:
        return list(_log_entries[-n:])


def get_log_stats():
    with _lock:
        total = len(_log_entries)
        levels = {"critical": 0, "warning": 0, "info": 0}
        for e in _log_entries:
            lv = e.get("level", "info")
            if lv in levels:
                levels[lv] += 1
        return {"total": total, **levels}
