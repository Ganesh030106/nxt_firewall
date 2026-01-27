#test_geo.py

#imports
import sys
import os
# Fix import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from scapy.all import IP, TCP, send
from src.database import log_event  # Now this will work

print("--- 🌍 TESTING GEO-BLOCKING ---")
print("Simulating traffic from CHINA (CN) and RUSSIA (RU)...")

# 1. Simulate IP from China (Beijing)
cn_ip = "223.255.255.255"
print(f"[>] Sending packet from {cn_ip} (China)...")
pkt1 = IP(src=cn_ip, dst="192.168.1.50")/TCP(dport=80, flags="S")
send(pkt1, verbose=0)

time.sleep(1)

# 2. Simulate IP from Russia (Moscow)
ru_ip = "2.92.255.255"
print(f"[>] Sending packet from {ru_ip} (Russia)...")
pkt2 = IP(src=ru_ip, dst="192.168.1.50")/TCP(dport=443, flags="S")
send(pkt2, verbose=0)

print("[✔] Packets sent. Check Dashboard for 'Geo-Block' alerts.")