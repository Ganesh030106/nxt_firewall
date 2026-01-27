#suspicious_port.py

#imports
import socket
import time

# TARGET CONFIGURATION
TARGET_IP = "8.8.8.8"
TARGET_PORT = 9999    # suspicious/Non-Standard Port

# ATTACK START
print(f"--- ⚠️  STARTING SUSPICIOUS PORT BEACONING ---")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")
print(f"Behavior: Connecting to undefined service port\n")

# BEACONING LOOP
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    
    result = sock.connect_ex((TARGET_IP, TARGET_PORT))
    
    # Send 5 beacon attempts
    for i in range(5):
        print(f"[>] Beaconing to Suspicious Port {TARGET_PORT}...")
        time.sleep(0.8)
        
    sock.close()
    print("\n[✔] Attack Complete. Check Dashboard for 'Suspicious Port Usage' alert.")

except Exception as e:
    print(f"\n[!] Attack interrupted: {e}")