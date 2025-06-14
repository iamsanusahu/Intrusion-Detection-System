"""
Intrusion Detection System (IDS)
Author: Sanu Kumar


A lightweight Python-based IDS that uses Scapy to sniff packets and detect
suspicious activity based on predefined IP or port rules.
"""

from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import json

# Load rule set
try:
    with open("rules.json", "r") as f:
        rules = json.load(f)
except FileNotFoundError:
    print("[ERROR] 'rules.json' not found. Please ensure the rules file is in the same directory.")
    exit(1)

# Alert logger
def log_alert(msg):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = f"[{timestamp}] {msg}"
    with open("alerts.log", "a") as f:
        f.write(alert + "\n")
    print(f"[ALERT] {alert}")

# Packet analyzer
def check_packet(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        for rule in rules:
            if rule["type"] == "ip" and rule["ip"] in [src, dst]:
                log_alert(f"Suspicious IP detected: {rule['ip']} from {src} to {dst}")
            if TCP in pkt and rule["type"] == "port" and pkt[TCP].dport == rule["port"]:
                log_alert(f"TCP port {rule['port']} access detected from {src}")
            if UDP in pkt and rule["type"] == "port" and pkt[UDP].dport == rule["port"]:
                log_alert(f"UDP port {rule['port']} access detected from {src}")

# Sniffer starter
if __name__ == "__main__":
    print("📡 Intrusion Detection System Started... Press Ctrl+C to stop.\n")
    sniff(filter="ip", prn=check_packet, store=False)
