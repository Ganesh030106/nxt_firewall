#large_payloads.py

import socket
import time

# TARGET CONFIGURATION
TARGET_IP = "8.8.8.8" # Google DNS (Simulating traffic leaving your network)
TARGET_PORT = 80      # Standard HTTP Port

# ATTACK START
print(f"--- ⚠️  STARTING LARGE PAYLOAD ATTACK ---")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")
print(f"Payload Size: 2500 bytes (Abnormal)\n")

# SENDING LARGE PAYLOADS
try:
    # Create a huge payload (2500 'X' characters)
    huge_payload = b"X" * 2500 
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    sock.connect((TARGET_IP, TARGET_PORT))
    
    # Send 5 large packets with short delays
    for i in range(5):
        sock.send(huge_payload)
        print(f"[>] Sent Malicious Packet {i+1} | Size: {len(huge_payload)} bytes")
        time.sleep(0.5)
        
    sock.close()
    print("\n[✔] Attack Complete. Check Dashboard for 'Large Payload Anomaly' alert.")

except Exception as e:
    print(f"\n[!] Attack interrupted: {e}")