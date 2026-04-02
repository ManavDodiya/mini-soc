# 🛡️ Mini SOC Platform

A fully integrated **Security Operations Center** platform built with Python + Flask.
Monitors network traffic, detects intrusions, scans web apps, monitors logs, and handles encrypted file transfer — all from a live terminal-style dashboard.

---

## 🚀 Quick Start

### Linux / macOS
```bash
cd mini-soc
chmod +x run.sh
./run.sh
```

### Windows
```
cd mini-soc
run.bat
```

Then open **http://127.0.0.1:5000** in your browser.

---

## 📁 Project Structure

```
mini-soc/
├── app.py                    ← Flask server + SocketIO API
├── requirements.txt          ← Python dependencies
├── run.sh / run.bat          ← One-click startup scripts
│
├── modules/
│   ├── network_monitor.py    ← Packet capture + IDS rules
│   ├── vuln_scanner.py       ← SQLi + XSS + header scanner
│   ├── log_monitor.py        ← System event log simulator
│   └── secure_transfer.py    ← AES-256 + RSA-2048 crypto
│
├── templates/
│   └── index.html            ← Live SOC dashboard (dark UI)
│
├── logs/                     ← Event log files (auto-created)
├── uploads/                  ← File upload staging
├── downloads/                ← Encrypted/decrypted outputs
└── keys/                     ← RSA key pairs (auto-generated)
```

---

## 🧩 Modules

### 1️⃣ Network Traffic Monitor + IDS (`modules/network_monitor.py`)
- Captures packets using **Scapy** (or simulates in demo mode)
- Analyzes IP, ports, protocols (TCP/UDP/ICMP)
- **IDS Rules:**
  - Port scan: 10+ distinct ports in 5 seconds → `CRITICAL` alert
  - DoS flood: 100+ packets in 2 seconds → `CRITICAL` alert
  - Brute force: 6+ attempts on SSH/FTP/RDP in 10 seconds → `WARNING`
- **Demo mode**: Realistic simulated traffic — no root required

### 2️⃣ Web Vulnerability Scanner (`modules/vuln_scanner.py`)
- Tests URLs for **SQL Injection** (8 payloads, error-based detection)
- Tests for **XSS** (8 payloads, reflection-based detection)
- Checks **Security Headers** (CSP, HSTS, X-Frame-Options, etc.)
- Crawls forms and tests GET/POST parameters
- Generates structured findings with severity levels

### 3️⃣ Log Monitor (`modules/log_monitor.py`)
- Simulates system events: logins, privilege escalation, config changes, firewall blocks
- Anomaly detection via threshold rules
- Writes to `logs/soc_events.log`
- Real-time stream to dashboard

### 4️⃣ Secure File Transfer (`modules/secure_transfer.py`)
- **AES-256-CBC** for file encryption
- **RSA-2048-OAEP** for AES key exchange
- **SHA-256** integrity verification post-decryption
- Auto-generates key pairs on first run
- Saves `.enc` JSON packages to `downloads/`

### 5️⃣ SOC Dashboard (`templates/index.html`)
- Real-time updates via **Socket.IO**
- Live packet feed, alert list, traffic charts
- Protocol distribution (doughnut chart)
- Attack injection buttons for demo
- Log stream with color-coded severity
- Crypto demo + file upload/download

---

## 🎯 Demo Workflow (for presentation)

1. **Start** the app → `./run.sh`
2. **Overview tab** — watch live traffic + packet counts auto-increment
3. **IDS/Network tab** → click "Port Scan" button → see CRITICAL alert appear
4. **IDS/Network tab** → click "DoS Flood" → see another alert
5. **Vuln Scanner tab** → click "Demo Target" → wait ~30s for scan results
6. **Log Monitor tab** — watch live event stream, filter by severity
7. **Secure Transfer tab** → click "Run Crypto Demo" → see AES+RSA in action
8. Upload any file → encrypt → download `.enc` → re-upload to decrypt

---

## ⚙️ Requirements

| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| flask-socketio | Real-time WebSocket push |
| scapy | Packet capture (optional, demo mode works without root) |
| requests + beautifulsoup4 | Web vulnerability scanner |
| pycryptodome | AES-256 + RSA-2048 encryption |
| eventlet | Async mode for SocketIO |

---

## 🔒 Legal Notice

This tool is for **educational and authorized use only**.  
Only scan systems you own or have explicit written permission to test.  
The vulnerability scanner includes a safe, intentionally vulnerable demo target (`testphp.vulnweb.com`).

---

## 👥 Team Division

| Member | Module |
|--------|--------|
| Member 1 | `network_monitor.py` — Scapy, IDS rules |
| Member 2 | `vuln_scanner.py` — SQLi, XSS detection |
| Member 3 | `log_monitor.py` + `app.py` — Flask, SocketIO |
| Member 4 | `secure_transfer.py` + Dashboard UI |
