#test_sinkhole.py
import sys
import socket
from scapy.all import IP, UDP, DNS, DNSQR, sr1

# Target Google DNS (Firewall should intercept this packet)
TARGET_IP = "8.8.8.8"
BAD_DOMAIN = "malware-c2.org"

# ATTACK START
print(f"--- 🕳️ TESTING DNS SINKHOLE ---")
print(f"Querying: {BAD_DOMAIN}")

try:
    # Construct DNS Packet
    pkt = IP(dst=TARGET_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=BAD_DOMAIN))
    
    # Send and wait for reply (Timeout 2s)
    response = sr1(pkt, timeout=2, verbose=0)

    if response and response.haslayer(DNS):
        # CHECK: Does the response actually have an Answer Section?
        if response[DNS].ancount == 0:
            print("[!] Received DNS Response, but it had NO answers.")
            print("    [Reason] Likely received 'NXDOMAIN' from real 8.8.8.8 before Firewall could inject fake IP.")
            print("    [Tip] Try running the test again. The Firewall logic relies on winning the race.")
        
        elif response[DNS].an:
            # Robustly get the IP data
            # Scapy structures answers as layers. We iterate to find the IP.
            answer_ip = None
            
            # Simple check for first answer
            try:
                answer_ip = response[DNS].an.rdata
            except:
                answer_ip = "Unknown Data"

            print(f"[<] Response Received: {answer_ip}")
            
            if answer_ip == "10.10.10.10":
                print("✅ SUCCESS: Domain was Sinkholed to 10.10.10.10!")
            else:
                print(f"❌ FAILED: Got real IP (or other data): {answer_ip}")
    else:
        print("[!] No response received (Packet dropped or timed out)")

except Exception as e:
    print(f"[!] Error sending packet: {e}")