#fake_attack_logs.py

import sys
import os
# Fix import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import random
from src.database import log_event

print("--- 📝 INJECTING FAKE LOGS FOR DEMO ---")

attacks = [
    ("192.168.1.105", "Port Scan Activity", "ALERT", 0.88),
    ("10.0.0.55", "Malicious C2 Blacklist", "BLOCKED", 1.0),
    ("45.33.22.11", "SQL Injection Attempt", "BLOCKED", 0.99),
    ("185.220.101.9", "Tor Exit Node", "BLOCKED", 0.95),
    ("172.16.5.14", "DDoS SYN Flood Detected", "BLOCKED", 0.97),
    ("203.0.113.8", "Brute Force Login Attempt", "ALERT", 0.91),
    ("198.51.100.42", "Data Exfiltration Suspected", "ALERT", 0.93),
    ("156.232.10.77", "Phishing Domain Access", "BLOCKED", 0.96),
    ("37.187.110.19", "Ransomware File Encryption Pattern", "BLOCKED", 0.99),
    ("102.54.94.97", "Unauthorized SMB Access", "ALERT", 0.89),
    ("192.0.2.90", "DNS Tunneling Activity", "ALERT", 0.92),
    ("64.233.160.21", "Suspicious Beaconing Traffic", "ALERT", 0.90),
    ("88.198.12.144", "Malware Payload Download Attempt", "BLOCKED", 0.98),
    ("77.247.110.32", "HTTP Directory Traversal Attack", "BLOCKED", 0.94),
    ("154.16.202.5", "ARP Spoofing / MITM Attempt", "ALERT", 0.87),
]

print("Injecting fake attack logs into the database...")

for ip, reason, action, conf in attacks:
    print(f"[+] Injecting log: {reason} from {ip}...")
    log_event(ip, "192.168.1.50", "TCP", action, conf, reason, "")
    time.sleep(0.5)

print("[✔] Fake logs injected successfully.")
