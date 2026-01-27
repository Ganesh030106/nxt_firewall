#test_threat_intel.py
import sys
import os
import requests
import re
import socket
from scapy.all import IP, TCP, send

# ATTACK START
# 1. Fetch a real malicious IP from the feed to use as our "Fake Source"
print("--- 🌍 FETCHING REAL MALICIOUS IP FOR TESTING ---")

# Fetch from Emerging Threats Compromised IPs Feed
try:
    r = requests.get("https://rules.emergingthreats.net/blockrules/compromised-ips.txt")
    real_malicious_ip = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', r.text)[0]
    print(f"[>] Found Active Threat IP: {real_malicious_ip}")
except:
    print("[!] Could not fetch feed. Using dummy.")
    real_malicious_ip = "1.2.3.4"

# 2. Simulate Attack
print(f"[>] Simulating Packet SPOOFED from {real_malicious_ip}...")

# Craft and send a TCP SYN packet with the spoofed source IP
pkt = IP(src=real_malicious_ip, dst="127.0.0.1")/TCP(dport=80, flags="S")

send(pkt, verbose=0)

print("[✔] Packet Sent. Check Dashboard for 'Global Threat Feed' alert.")