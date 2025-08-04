import socket
import threading
import datetime
import smtplib
from email.message import EmailMessage
import requests
import http.server
import socketserver
import os
import re

# ------------------------ CONFIGURATION ------------------------ #
LOG_FILE = "honeypot_logs.txt"
HOST = "0.0.0.0"
PORT = 2222
REDIRECT_PORT = 8080
REDIRECT_URL = "https://secure-national-bank-clone.vercel.app"

# Gmail alert settings
FROM_EMAIL = "aalageely@gmail.com"
TO_EMAIL = "Danaalageely88@gmail.com"
APP_PASSWORD = "mkbc nxsa upag uqzs"

# Telegram alert settings
TELEGRAM_TOKEN = "8389627211:AAGq6tuHxuLKX9m4AQR-ljj77z-GjKrpIig"
CHAT_ID = "1919975349"

# Firebase settings
FIREBASE_URL = "https://honeypot-715b9-default-rtdb.firebaseio.com/honeypot_logs.json"

# ------------------------ ATTACK CLASSIFICATION ------------------------ #
def classify_attack(payload):
    signatures = {
        "Brute Force": [r"password", r"login", r"root", r"admin"],
        "Port Scan": [r"nmap", r"scan", r"NULL", r"\\x00", r"libssh"],
        "Command Injection": [r";", r"\\|\\|", r"&&", r"/bin/sh", r"bash", r"wget", r"curl"],
        "SQL Injection": [r"' OR 1=1", r"SELECT .* FROM", r"UNION SELECT"],
        "Malware Drop": [r".exe", r".sh", r"powershell", r"python", r"base64"],
        "Reconnaissance": [r"whoami", r"uname", r"id", r"ifconfig", r"netstat"]
    }

    for category, patterns in signatures.items():
        for pattern in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                return category
    return "Unclassified"

# ------------------------ ALERT FUNCTIONS ------------------------ #
def send_email_alert(ip, port, data, category):
    msg = EmailMessage()
    msg["Subject"] = "🚨 Honeypot Alert - Connection Detected"
    msg["From"] = FROM_EMAIL
    msg["To"] = TO_EMAIL
    msg.set_content(f"""
🚨 Suspicious activity detected on the honeypot:

📍 IP Address: {ip}
📌 Port: {port}
🧾 Category: {category}
🕒 Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
📥 Payload: {data.strip()}
    """)
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(FROM_EMAIL, APP_PASSWORD)
            smtp.send_message(msg)
        print(f"[✔] Email alert sent to {TO_EMAIL}")
    except Exception as e:
        print(f"[✖] Failed to send email: {e}")

def send_telegram_alert(ip, port, data, category):
    message = f"""🚨 *Honeypot Alert Detected*

🔍 *IP:* `{ip}`
🔌 *Port:* `{port}`
🧾 *Category:* `{category}`
🕒 *Time:* `{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
📥 *Payload:* `{data.strip()}`"""

    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": CHAT_ID,
        "text": message,
        "parse_mode": "Markdown"
    }

    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            print("[✔] Telegram alert sent.")
        else:
            print(f"[✖] Telegram failed: {response.text}")
    except Exception as e:
        print(f"[✖] Telegram error: {e}")

def send_to_firebase(ip, port, data, category):
    payload = {
        "ip": ip,
        "port": port,
        "category": category,
        "time": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "data": data.strip()
    }
    try:
        r = requests.post(FIREBASE_URL, json=payload)
        if r.status_code == 200:
            print("[✔] Sent to Firebase")
        else:
            print(f"[✖] Firebase failed: {r.text}")
    except Exception as e:
        print(f"[✖] Firebase error: {e}")

# ------------------------ LOGGING FUNCTION ------------------------ #
def log_attempt(addr, data):
    category = classify_attack(data)
    timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    log = f"[{timestamp}] Connection from {addr[0]}:{addr[1]} - Category: {category} - Data: {data.strip()}"
    print(log)

    with open(LOG_FILE, "a") as f:
        f.write(log + "\\n")

    send_email_alert(addr[0], addr[1], data, category)
    send_telegram_alert(addr[0], addr[1], data, category)
    send_to_firebase(addr[0], addr[1], data, category)

# ------------------------ NMAP DETECTION ------------------------ #
def is_nmap_probe(data):
    suspicious_signatures = ["nmap", "libssh", "masscan", "scan", "NULL", "\\x00"]
    lower_data = data.lower()
    return any(sig in lower_data for sig in suspicious_signatures)

# ------------------------ HTTP REDIRECTION SERVER ------------------------ #
class RedirectHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(302)
        self.send_header('Location', REDIRECT_URL)
        self.end_headers()

# ------------------------ CLIENT HANDLER ------------------------ #
def handle_client(client_socket, addr):
    try:
        client_socket.sendall(b"SSH-2.0-OpenSSH_7.9p1 Debian\\n")
        data = client_socket.recv(1024)
        if not data:
            data = b"NO DATA RECEIVED"
        decoded_data = data.decode("utf-8", errors="ignore")

        if is_nmap_probe(decoded_data):
            log_attempt(addr, f"NMAP PROBE: {decoded_data}")
        else:
            log_attempt(addr, decoded_data)
    except Exception as e:
        log_attempt(addr, f"ERROR READING DATA: {str(e)}")
    finally:
        client_socket.close()

# ------------------------ MAIN HONEYPOT ------------------------ #
def start_honeypot():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(5)
    print(f"[+] SSH Honeypot running on port {PORT}...")
    while True:
        client, addr = server.accept()
        threading.Thread(target=handle_client, args=(client, addr)).start()

# ------------------------ MAIN REDIRECTOR ------------------------ #
def start_redirector():
    handler = RedirectHandler
    httpd = socketserver.TCPServer((HOST, REDIRECT_PORT), handler)
    print(f"[+] Redirect server running on port {REDIRECT_PORT}...")
    httpd.serve_forever()

# ------------------------ MAIN ENTRY POINT ------------------------ #
if __name__ == "__main__":
    threading.Thread(target=start_redirector, daemon=True).start()
    start_honeypot()