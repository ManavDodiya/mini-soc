"""
Mini SOC Platform — Flask Application
REST API + Server-Sent Events for real-time push (no external socketio needed)
"""

import os, json, threading, time, queue
from pathlib import Path
from flask import Flask, render_template, jsonify, request, send_from_directory, Response, stream_with_context

from modules.network_monitor import (start_monitor, get_recent_packets,
    get_recent_alerts, get_stats, inject_attack)
from modules.log_monitor import start_log_monitor, get_recent_logs, get_log_stats
from modules.secure_transfer import (encrypt_file, decrypt_file, get_transfer_log,
    load_or_create_keypair, demo_encrypt_decrypt)
from modules.vuln_scanner import scan as vuln_scan, demo_scan

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

DOWNLOAD_DIR = Path("downloads")
DOWNLOAD_DIR.mkdir(exist_ok=True)

_scan_running = False
_scan_result = None

# ── SSE subscriber queues ─────────────────────────────────────────────────────
_sse_clients = []
_sse_lock = threading.Lock()

def _broadcast(data: dict):
    msg = "data: " + json.dumps(data) + "\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_clients:
            try:
                q.put_nowait(msg)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_clients.remove(q)

def _push_loop():
    while True:
        time.sleep(2)
        try:
            _broadcast({
                "packets":   get_recent_packets(20),
                "alerts":    get_recent_alerts(10),
                "stats":     get_stats(),
                "logs":      get_recent_logs(20),
                "log_stats": get_log_stats(),
            })
        except Exception:
            pass

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/stream")
def sse_stream():
    q = queue.Queue(maxsize=20)
    with _sse_lock:
        _sse_clients.append(q)
    def generate():
        yield "data: {\"connected\": true}\n\n"
        while True:
            try:
                msg = q.get(timeout=30)
                yield msg
            except queue.Empty:
                yield ": ping\n\n"
            except GeneratorExit:
                break
        with _sse_lock:
            try: _sse_clients.remove(q)
            except ValueError: pass
    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})

@app.route("/api/packets")
def api_packets():
    return jsonify(get_recent_packets(int(request.args.get("n", 50))))

@app.route("/api/alerts")
def api_alerts():
    return jsonify(get_recent_alerts(int(request.args.get("n", 30))))

@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())

@app.route("/api/inject_attack", methods=["POST"])
def api_inject_attack():
    data = request.get_json(force=True) or {}
    t = data.get("type", "port_scan")
    if t not in ("port_scan", "dos", "brute_force"):
        return jsonify({"error": "invalid type"}), 400
    return jsonify(inject_attack(t))

@app.route("/api/logs")
def api_logs():
    return jsonify(get_recent_logs(int(request.args.get("n", 100))))

@app.route("/api/log_stats")
def api_log_stats():
    return jsonify(get_log_stats())

@app.route("/api/scan", methods=["POST"])
def api_scan():
    global _scan_running, _scan_result
    data = request.get_json(force=True) or {}
    url = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "url required"}), 400
    if _scan_running:
        return jsonify({"error": "Scan already running"}), 409
    _scan_running = True
    _scan_result = None
    def run():
        global _scan_running, _scan_result
        try:
            _scan_result = vuln_scan(url)
        except Exception as e:
            _scan_result = {"error": str(e), "target": url}
        finally:
            _scan_running = False
            _broadcast({"scan_complete": _scan_result})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started", "target": url})

@app.route("/api/scan/demo", methods=["POST"])
def api_scan_demo():
    global _scan_running, _scan_result
    if _scan_running:
        return jsonify({"error": "Scan already running"}), 409
    _scan_running = True
    _scan_result = None
    def run():
        global _scan_running, _scan_result
        try:
            _scan_result = demo_scan()
        except Exception as e:
            _scan_result = {"error": str(e)}
        finally:
            _scan_running = False
            _broadcast({"scan_complete": _scan_result})
    threading.Thread(target=run, daemon=True).start()
    return jsonify({"status": "started", "target": "testphp.vulnweb.com"})

@app.route("/api/scan/status")
def api_scan_status():
    return jsonify({"running": _scan_running, "result": _scan_result})

@app.route("/api/keys/generate", methods=["POST"])
def api_gen_keys():
    keys = load_or_create_keypair()
    return jsonify({"public_key": keys["public_key"],
                    "private_key_file": keys.get("private_key_file","loaded")})

@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    keys = load_or_create_keypair()
    result = encrypt_file(f.read(), keys["public_key"], f.filename)
    safe = {k: result[k] for k in
            ("filename","sha256","original_size","algorithm","encrypted_at","output_file")}
    safe["encrypted_key_preview"] = result["encrypted_key"][:60] + "..."
    safe["nonce"] = result["nonce"]
    return jsonify(safe)

@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    try:
        package = json.loads(f.read().decode())
    except Exception:
        return jsonify({"error": "Invalid .enc file"}), 400
    keys = load_or_create_keypair()
    return jsonify(decrypt_file(package, keys["private_key"]))

@app.route("/api/transfer/demo", methods=["POST"])
def api_transfer_demo():
    return jsonify(demo_encrypt_decrypt())

@app.route("/api/transfer/log")
def api_transfer_log():
    return jsonify(get_transfer_log())

@app.route("/api/download/<filename>")
def api_download(filename):
    return send_from_directory(str(DOWNLOAD_DIR.absolute()), filename, as_attachment=True)

# ── Startup ───────────────────────────────────────────────────────────────────
def start_services():
    start_monitor(demo_mode=True)
    start_log_monitor()
    threading.Thread(target=_push_loop, daemon=True).start()

if __name__ == "__main__":
    print("\n" + "="*50)
    print("  🛡️  Mini SOC Platform")
    print("  → http://127.0.0.1:5000")
    print("="*50 + "\n")
    start_services()
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
