import argparse
import json
import os
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
RULES_FILE = BASE_DIR / "ids_demo.rules"
FAST_LOG = BASE_DIR / "ids_fast.log"
EVE_LOG = BASE_DIR / "ids_eve.jsonl"
LISTEN_HOST = "127.0.0.1"
LISTEN_PORTS = (2222, 8080, 8443)
PORT_SCAN_WINDOW = 2.0
PORT_SCAN_THRESHOLD = 3
SSH_WINDOW = 10.0
SSH_THRESHOLD = 5


class DemoSensor:
    def __init__(self):
        self.scan_tracker = defaultdict(deque)
        self.ssh_tracker = defaultdict(deque)
        self.alerts = []
        self.lock = threading.Lock()

    def handle_connection(self, src_ip, src_port, dst_port, payload):
        now = time.time()
        self._track_scan(src_ip, src_port, dst_port, now)
        if dst_port == 2222 and payload.startswith("AUTH "):
            self._track_ssh_bruteforce(src_ip, src_port, dst_port, payload, now)

    def _track_scan(self, src_ip, src_port, dst_port, now):
        history = self.scan_tracker[src_ip]
        history.append((now, dst_port))
        while history and now - history[0][0] > PORT_SCAN_WINDOW:
            history.popleft()
        unique_ports = sorted({port for _, port in history})
        if len(unique_ports) >= PORT_SCAN_THRESHOLD:
            self._alert(
                sid=1000001,
                message="LOCAL Port scan detected",
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=LISTEN_HOST,
                dst_port=dst_port,
                proto="TCP",
                extra={"scanned_ports": unique_ports},
            )
            history.clear()

    def _track_ssh_bruteforce(self, src_ip, src_port, dst_port, payload, now):
        history = self.ssh_tracker[src_ip]
        history.append((now, payload))
        while history and now - history[0][0] > SSH_WINDOW:
            history.popleft()
        if len(history) >= SSH_THRESHOLD:
            self._alert(
                sid=1000002,
                message="LOCAL SSH brute-force pattern detected",
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=LISTEN_HOST,
                dst_port=dst_port,
                proto="TCP",
                extra={"attempts": len(history)},
            )
            history.clear()

    def _alert(self, sid, message, src_ip, src_port, dst_ip, dst_port, proto, extra):
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        fast_line = (
            f"{timestamp}  [**] [1:{sid}:1] {message} [**] "
            f"[Classification: Attempted Information Leak] [Priority: 2] "
            f"{{{proto}}} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
        )
        eve_event = {
            "timestamp": timestamp,
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": proto,
            "alert": {
                "signature_id": sid,
                "signature": message,
                "severity": 2,
            },
            "metadata": extra,
        }
        with self.lock:
            self.alerts.append(fast_line)
            with FAST_LOG.open("a", encoding="utf-8") as fast_file:
                fast_file.write(fast_line + "\n")
            with EVE_LOG.open("a", encoding="utf-8") as eve_file:
                eve_file.write(json.dumps(eve_event) + "\n")


def ensure_rules_file():
    if RULES_FILE.exists():
        return
    RULES_FILE.write_text(
        "\n".join(
            [
                'alert tcp any any -> $HOME_NET any (msg:"LOCAL Port scan detected"; flow:stateless; sid:1000001; rev:1;)',
                'alert tcp any any -> $HOME_NET 22 (msg:"LOCAL SSH brute-force pattern detected"; flow:to_server,established; sid:1000002; rev:1;)',
                "",
            ]
        ),
        encoding="utf-8",
    )


def reset_logs():
    for path in (FAST_LOG, EVE_LOG):
        if path.exists():
            path.unlink()


def serve_port(sensor, port, stop_event):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LISTEN_HOST, port))
    server.listen(5)
    server.settimeout(0.5)
    while not stop_event.is_set():
        try:
            client, addr = server.accept()
        except socket.timeout:
            continue
        with client:
            client.settimeout(0.5)
            try:
                payload = client.recv(1024).decode("utf-8", errors="ignore").strip()
            except socket.timeout:
                payload = ""
            sensor.handle_connection(addr[0], addr[1], port, payload)
            if port == 2222 and payload.startswith("AUTH "):
                client.sendall(b"AUTH FAIL\n")
            else:
                client.sendall(b"OK\n")
    server.close()


def connect_and_send(port, payload=""):
    with socket.create_connection((LISTEN_HOST, port), timeout=2) as sock:
        if payload:
            sock.sendall(payload.encode("utf-8"))
        try:
            sock.recv(1024)
        except socket.timeout:
            pass


def run_demo():
    ensure_rules_file()
    reset_logs()
    sensor = DemoSensor()
    stop_event = threading.Event()
    threads = []
    for port in LISTEN_PORTS:
        thread = threading.Thread(target=serve_port, args=(sensor, port, stop_event), daemon=True)
        thread.start()
        threads.append(thread)

    time.sleep(0.5)
    for port in LISTEN_PORTS:
        connect_and_send(port)
        time.sleep(0.15)

    for attempt in range(SSH_THRESHOLD):
        connect_and_send(2222, payload=f"AUTH demo wrong-password-{attempt}\n")
        time.sleep(0.1)

    time.sleep(0.5)
    stop_event.set()
    for thread in threads:
        thread.join(timeout=1)
    return sensor.alerts


def print_summary():
    print("Rules loaded from:", RULES_FILE.name)
    print(RULES_FILE.read_text(encoding="utf-8").strip())
    print()
    print("Fast alerts:")
    if FAST_LOG.exists():
        print(FAST_LOG.read_text(encoding="utf-8").strip())
    print()
    print("EVE alerts:")
    if EVE_LOG.exists():
        print(EVE_LOG.read_text(encoding="utf-8").strip())


def main():
    parser = argparse.ArgumentParser(description="Educational IDS demo for localhost scans.")
    parser.add_argument("--demo", action="store_true", help="Run the bundled scan and brute-force demo.")
    parser.add_argument("--show-only", action="store_true", help="Print existing rules and alert logs.")
    args = parser.parse_args()

    ensure_rules_file()
    if args.demo:
        alerts = run_demo()
        print(f"Triggered {len(alerts)} alerts.")
        for alert in alerts:
            print(alert)
        print()
        print_summary()
        return
    if args.show_only:
        print_summary()
        return
    parser.print_help()


if __name__ == "__main__":
    main()
