import requests
import time
import sys

# Target the Protected Server
TARGET_URL = "http://127.0.0.1:8080"
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}

print(f"--- 💉 LAUNCHING SQL INJECTION TEST (DPI) ---")
print(f"[*] Target: {TARGET_URL}")

# Real-world payloads used by hackers
payloads = [
    "' OR '1'='1",
    "admin' --",
    "UNION SELECT 1, @@version --",
    "<script>alert('XSS_ATTACK')</script>",
    "../../etc/passwd"  # Directory Traversal
]

for p in payloads:
    print(f"[>] Injecting Payload: {p}")
    try:
        # Send a REAL HTTP GET Request
        # The Firewall sniffer will intercept this packet instantly
        response = requests.get(TARGET_URL, params={"search": p}, headers=HEADERS, timeout=2)
        
        if response.status_code == 200:
            print("    [?] Server Responded (200 OK). Check Dashboard to see if it was flagged.")
        else:
            print(f"    [!] Server Error: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("    [x] Connection Failed (Firewall Blocked it?)")
    except Exception as e:
        print(f"    [!] Error: {e}")
    
    time.sleep(1) # Pause to let logs update

print("\n[✔] Attack Sequence Complete.")