import os
import datetime
import threading
from scapy.all import wrpcap

# Path Setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
PCAP_FOLDER = os.path.join(PROJECT_ROOT, "logs", "pcaps")

# Ensure the folder exists
if not os.path.exists(PCAP_FOLDER):
    os.makedirs(PCAP_FOLDER)

def _write_pcap_thread(packet, filename):
    """
    Background worker to write the file so the main thread doesn't freeze.
    """
    try:
        filepath = os.path.join(PCAP_FOLDER, filename)
        # Write the packet containing the payload
        wrpcap(filepath, packet)
    except Exception as e:
        print(f"[ERROR] Failed to write PCAP: {e}")

def capture_attack_packet(packet, attack_type):
    """
    Triggers the capture.
    Returns the filename to be stored in the database.
    """
    try:
        # 1. Generate Unique Filename
        # Format: AttackType_Timestamp_SrcIP.pcap
        # Sanitize attack type string for filename safety
        safe_type = attack_type.replace(" ", "_").replace(":", "").replace("/", "")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Scapy packet indexing for IP source (safeguard)
        src_ip = packet[0][1].src if packet.haslayer('IP') else "Unknown"
        
        filename = f"{safe_type}_{timestamp}_{src_ip}.pcap"
        
        # 2. Spawn Background Thread (Performance Protection)
        # We use threading so the Firewall loop doesn't wait for Disk I/O
        t = threading.Thread(target=_write_pcap_thread, args=(packet, filename))
        t.start()
        
        return filename
    except Exception as e:
        print(f"[ERROR] PCAP Init Failed: {e}")
        return ""