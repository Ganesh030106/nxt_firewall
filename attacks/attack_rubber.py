import keyboard
import time
import sys

print("--- 🦆 RUBBER DUCKY SIMULATION ---")
print("⚠️ WARNING: YOUR PC WILL LOCK IF SENTINEL IS WORKING ⚠️")
print("You have 3 seconds to cancel (CTRL+C)...")

time.sleep(3)

print("[*] Injecting malicious payload at SUPERHUMAN speed...")

# Long payload to ensure we hit the 15-key threshold
payload = "powershell_invoke_malware_download_payload_execution_sequence_start"

try:
    # delay=0.005 is 5ms per key (Human avg is 100ms+)
    # This is fast enough to trigger the 50ms threshold easily
    keyboard.write(payload, delay=0.005)
    
    print("[?] Payload sent. Waiting for response...")
    time.sleep(5)
    
except Exception as e:
    print(f"[!] Error: {e}")