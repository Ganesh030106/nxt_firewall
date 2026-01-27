#test_honeypot.py

#imports
import socket
import time

# TARGET CONFIGURATION
TARGET_IP = "127.0.0.1"
TARGET_PORT = 2323  # The Honeypot Port

# ATTACK START
print(f"--- 🍯 ATTEMPTING TO CONNECT TO HONEYPOT ---")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")

# CONNECTION ATTEMPT
try:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    
    print("[>] Connecting...")
    sock.connect((TARGET_IP, TARGET_PORT))
    
    # If we get here, the honeypot accepted us (and then logged us)
    print("[!] Connection Established! (You have been flagged)")
    
    # Try to grab the banner
    banner = sock.recv(1024)
    print(f"[<] Received Banner: {banner.decode().strip()}")
    
    sock.close()
    print("\n[✔] Attack Complete. Check Dashboard for 'Honeypot Trap' alert.")

except Exception as e:
    print(f"\n[!] Connection Failed: {e}")