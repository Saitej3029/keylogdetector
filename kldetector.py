import psutil
import os
import socket
import subprocess
import requests
import hashlib
import time
from pynput.keyboard import Controller

# ====== CONFIGURATION ======
SUSPICIOUS_PROCESSES = ["keylog", "stealth", "logger", "spy", "record"]
WHITELIST_PROCESSES = ["explorer.exe", "chrome.exe", "firefox.exe", "python.exe"]

TELEGRAM_BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_TELEGRAM_CHAT_ID"
VIRUSTOTAL_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

keyboard_controller = Controller()

# ====== ALERT FUNCTION ======
def send_alert(message):
    """Sends alerts to Telegram."""
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
        try:
            requests.post(url, data=data)
        except Exception as e:
            print(f"Failed to send alert: {e}")

# ====== DETECTION FUNCTIONS ======
def detect_suspicious_processes():
    """Detects and terminates keylogger processes."""
    found = []
    for process in psutil.process_iter(attrs=['pid', 'name']):
        try:
            proc_name = process.info['name'].lower()
            if any(susp in proc_name for susp in SUSPICIOUS_PROCESSES) and proc_name not in WHITELIST_PROCESSES:
                found.append((proc_name, process.info['pid']))
                print(f"[❌] Terminating {proc_name} (PID: {process.info['pid']})")
                psutil.Process(process.info['pid']).terminate()
                send_alert(f"🚨 *Terminated Suspicious Process:* {proc_name} (PID: {process.info['pid']})")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return found

def detect_keyboard_hooks():
    """Detects keyboard hooks (Windows only)."""
    try:
        output = subprocess.check_output("tasklist /v", shell=True).decode()
        if any("pynput" in line.lower() or "keylogger" in line.lower() for line in output.split("\n")):
            print("[⚠️] WARNING: A keyboard hook was detected!")
            send_alert("🚨 *Keyboard Hook Detected!* Possible keylogger activity.")
            return True
    except Exception as e:
        print(f"Error detecting keyboard hooks: {e}")
    return False

def detect_suspicious_network_activity():
    """Detects active network connections to unknown IPs."""
    suspicious_connections = []
    for conn in psutil.net_connections(kind='inet'):
        if conn.status == psutil.CONN_ESTABLISHED:
            try:
                remote_ip = conn.raddr.ip
                hostname = socket.gethostbyaddr(remote_ip)[0]
                if "unknown" in hostname or not hostname.endswith(("com", "net", "org")):
                    suspicious_connections.append(remote_ip)
            except:
                suspicious_connections.append(conn.raddr.ip)
    
    if suspicious_connections:
        print("[⚠️] Suspicious Network Connections Found:")
        for ip in suspicious_connections:
            print(f"   → {ip}")
        send_alert(f"🚨 *Suspicious Network Activity Detected!* IPs: {suspicious_connections}")

    return suspicious_connections

def check_virustotal(file_path):
    """Scans a process file in VirusTotal."""
    try:
        # Get file hash
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            vt_data = response.json()
            detections = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            if detections.get("malicious", 0) > 0:
                print(f"[⚠️] VirusTotal flagged {file_path} as MALICIOUS!")
                send_alert(f"🚨 *VirusTotal Alert:* {file_path} flagged as MALICIOUS!")
                return True
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
    return False

def detect_fake_keypress():
    """Detects software-injected keystrokes."""
    print("[🕵️] Detecting fake key presses...")
    before = len(psutil.pids())  
    keyboard_controller.type("TESTKEY")
    time.sleep(2)  
    after = len(psutil.pids())  

    if after > before:
        print("[⚠️] WARNING: A keylogger might be capturing fake keystrokes!")
        send_alert("🚨 *Keylogger Detected!* Fake keystroke test triggered a response.")

def scan_for_keylogger_logs():
    """Scans for suspicious hidden log files."""
    suspicious_logs = []
    scan_dirs = ["/tmp/", os.path.expanduser("~"), "/var/log/", "C:\\Users\\Public\\"]

    for scan_dir in scan_dirs:
        try:
            for root, _, files in os.walk(scan_dir):
                for file in files:
                    if any(ext in file for ext in [".log", ".txt", ".dat"]):
                        full_path = os.path.join(root, file)
                        if os.stat(full_path).st_size > 1024:  
                            suspicious_logs.append(full_path)
        except Exception:
            continue

    if suspicious_logs:
        print("[⚠️] Found suspicious keylogger logs:")
        for log in suspicious_logs:
            print(f"   → {log}")
        send_alert(f"🚨 *Suspicious Keylogger Logs Found!* {suspicious_logs}")

def detect_hidden_processes():
    """Detects hidden processes that don't appear in task manager."""
    try:
        output = subprocess.check_output("tasklist /FO TABLE /NH", shell=True).decode()
        hidden_count = sum(1 for line in output.split("\n") if "N/A" in line)

        if hidden_count > 0:
            print(f"[⚠️] WARNING: {hidden_count} hidden processes detected!")
            send_alert(f"🚨 *Hidden Processes Detected!* Count: {hidden_count}")
    except Exception as e:
        print(f"Error detecting hidden processes: {e}")

# ====== MAIN FUNCTION ======
def main():
    print("[🔍] Running Keylogger Detector...\n")

    detect_suspicious_processes()
    detect_keyboard_hooks()
    detect_suspicious_network_activity()
    detect_fake_keypress()
    scan_for_keylogger_logs()
    detect_hidden_processes()

    print("\n[✅] Scan Complete!")

if __name__ == "__main__":
    main()
