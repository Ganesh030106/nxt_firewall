# src/firewall.py

#imports
import os
import joblib
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP, send, conf, Raw, send, DNS, DNSQR 
import threading
import time
import subprocess
import requests                             # For Admin Dashboard Integration
from multiprocessing import Process, Queue  # Multiprocessing
from collections import defaultdict

# Internal modules imports
from src.socket_handler import socketio
from src.voice import speak_message
from src.database import get_custom_rules, log_event, update_heartbeat, get_whitelist, log_system_event
from src.dpi import inspect_payload
from src.geo import check_geo_block
from src.forensics import capture_attack_packet 
from src.dns_security import is_dns_tunneling, check_malicious_domain, forge_sinkhole_response
from src.feedback import load_feedback_model, check_feedback_override
from src.threat_intel import start_threat_intel_updater, is_global_threat 
from src.dl_traffic import predict_traffic_anomaly
from src.zero_trust import enforce_zero_trust


# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
BRAIN_PATH = os.path.join(PROJECT_ROOT, "models", "real_firewall_brain.pkl")
ADMIN_API_URL = "http://127.0.0.1:5001/api/alert"  # Admin Dashboard Endpoint

# [ENHANCEMENT CONFIG] Flow-Based Thresholds
DDOS_THRESHOLD = 50        # Max packets per second (Velocity Limit)
DDOS_BAN_TIME = 60         # Ban duration in seconds

# --- STATE TRACKING (Flow Analysis Tables) ---
# Tracks velocity: { '192.168.1.5': 42 } (Packets this second)
packet_counts = defaultdict(int)   

# Tracks bans: { '192.168.1.5': 17000000.0 } (Timestamp when ban expires)
blocked_ips = {}                   

last_reset_time = time.time()
port_scans = defaultdict(set)
MALICIOUS_IPS = ["192.168.56.101", "10.0.0.55"]
ACTIVE_RULES = {"IP": set(), "PORT": set()}

# --- SHARED QUEUE ---
# This queue connects the fast Sniffer Process to the smart Analyzer Thread
packet_queue = Queue()

import multiprocessing

# --- LOAD AI MODEL (Your Logic) ---
model = None
encoders = None
feedback_model = None

def _bg_load_firewall_models():
    global model, encoders, feedback_model
    print(f"[DEBUG] Looking for AI Brain at: {BRAIN_PATH}")
    if os.path.exists(BRAIN_PATH):
        try:
            data = joblib.load(BRAIN_PATH)
            model = data["model"]
            encoders = data["encoders"]
            print("[INFO] Sentinel-X Packet AI Loaded Successfully.")
        except Exception as e:
            print(f"[WARN] AI Model Load Failed: {e}")
    else:
        print("[WARN] No AI Model found. Running in 'Rules-Only' Mode.")

    try:
        feedback_model = load_feedback_model()
        if feedback_model:
            print("[INFO] User Feedback Model Loaded (False Positive Corrector).")
        else:
            print("[INFO] No Feedback Model found (will be created after first feedback).")
    except Exception as e:
        print(f"[WARN] Failed to load Feedback Model: {e}")

# Only load model in the MainProcess to avoid child process loading overhead
if multiprocessing.current_process().name == 'MainProcess':
    threading.Thread(target=_bg_load_firewall_models, daemon=True).start()

# --- HELPER FUNCTIONS ---
def get_service_name(port):
    # Map common ports to service names for the AI
    services = {80: "http", 443: "http", 21: "ftp", 22: "ssh", 25: "smtp", 53: "domain_u"}
    return services.get(port, "private")

def get_flag_name(flags):
    # Scapy flags are 0x02 (S), 0x10 (A), etc. Map to NSL-KDD names.
    f_str = str(flags)
    if "S" in f_str and "A" not in f_str: return "S0"   # SYN Only
    if "S" in f_str and "A" in f_str: return "SF"       # SYN-ACK
    if "R" in f_str: return "REJ"                       # Reset
    return "SF" # Default normal

def notify_admin(src_ip, message):
    """Sends a critical alert to the Admin C2 Server"""
    try:
        requests.post(ADMIN_API_URL, json={
            "source": src_ip,
            "message": message
        }, timeout=1)
    except:
        pass # Fail silently if Admin server is offline

def heartbeat_loop():
    while True:
        update_heartbeat()
        time.sleep(5)
    
def refresh_firewall_rules():
    """Reloads all rules from DB into Memory"""
    global ACTIVE_RULES
    rules = get_custom_rules()

    # Reset Cache
    new_cache = {"IP": set(), "PORT": set()}

    for r in rules:
        if r['type'] == 'IP':
            new_cache['IP'].add(r['value'])
        elif r['type'] == 'PORT':
            new_cache['PORT'].add(int(r['value']))

    ACTIVE_RULES = new_cache
    print(f"[INFO] Firewall Rules Reloaded: {len(ACTIVE_RULES['IP'])} IPs, {len(ACTIVE_RULES['PORT'])} Ports blocked.")

# --- MAIN PACKET PROCESSING LOGIC ---
def process_packet(packet):
        global last_reset_time, blocked_ips, packet_counts

        # 1. BASIC VALIDATION
        if not packet.haslayer(IP): return 
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"
        current_time = time.time()
        pkt_len = len(packet)

        # [PREVENTION LAYER] 2. DROP & BAN MECHANISM (EARLY DROP)
        
        # This is the "Wall". If an IP is banned, we drop HERE.
        # We do NOT let it reach AI, DPI, or Database logic.
        # This saves massive CPU during a flood.
        if src_ip in blocked_ips:
            if current_time < blocked_ips[src_ip]:
                # SILENT DROP (Returns immediately)
                return 
            else:
                # Ban Expired -> Remove from jail
                del blocked_ips[src_ip]
                print(f"[INFO] Unbanned IP: {src_ip}")

        
        # [DETECTION LAYER] 3. VELOCITY CHECK (TRIGGER BAN)
        
        # Reset counters every 1 second
        if current_time - last_reset_time > 1.0:
            packet_counts.clear()
            last_reset_time = current_time

        packet_counts[src_ip] += 1
        
        # If Velocity > 50 packets/sec -> BAN IT
        if packet_counts[src_ip] > DDOS_THRESHOLD:
            msg = f"DDoS Flood Detected ({packet_counts[src_ip]} packets/sec)"
            print(f"\n[CRITICAL] {msg} from {src_ip}")
            
            # ACTION: Add to Temporal Blocklist
            blocked_ips[src_ip] = current_time + DDOS_BAN_TIME
            
            # --- NEW ADDITIONS ---
            speak_message(f"DDoS Attack Detected. Blocking IP {src_ip}")   # 🔊 VOICE ALERT
            socketio.emit('force_update', {'msg': f'DDoS Blocked: {src_ip}'}) # ⚡ WEBSOCKET PUSH
            # ---------------------
            
            log_event(src_ip, dst_ip, protocol, "BLOCKED", 1.0, msg, "")
            return # Drop this packet
        
        # 4. WHITELIST CHECK

        if src_ip in get_whitelist(): return

        # 5. ZERO TRUST ENFORCEMENT

        # Determine protocol/len for context
        proto_name = "tcp" 
        if packet.haslayer(UDP): proto_name = "udp"
        is_allowed, zt_msg = enforce_zero_trust(src_ip, proto_name, pkt_len)
        if not is_allowed:
            print(f"\n[BLOCK] {zt_msg}")
            log_event(src_ip, dst_ip, "ZTA", "BLOCKED", 1.0, "Zero Trust Policy", "")
            notify_admin(src_ip, zt_msg)
            return # Stop processing

        # 6. DEEP LEARNING TRAFFIC ANOMALY DETECTION(LSTM) - Volume Trends

        # We feed the current packet size to the LSTM
        is_anomaly, exp_vol, variance = predict_traffic_anomaly(pkt_len)
        if is_anomaly:
            msg = f"Traffic Anomaly detected by LSTM (Var: {variance:.2f})"
            print(f"\n[ALERT] {msg}")
            # We might not BLOCK immediately on anomaly, just ALERT for now
            log_event(src_ip, dst_ip, "AI", "ALERT", 0.85, "LSTM Traffic Anomaly", "")

        # 7. DYNAMIC RULE ENGINE CHECK

        # Check 1: Blocked IPs
        if src_ip in ACTIVE_RULES['IP']:
            print(f"\n[BLOCK] Custom Rule Enforced: Blocked IP {src_ip}")
            log_event(src_ip, dst_ip, "IP", "BLOCKED", 1.0, "Custom Blacklist Rule", "")
            return

        if packet.haslayer(TCP) and packet[TCP].dport in ACTIVE_RULES['PORT']:
                print(f"\n[BLOCK] Custom Rule Enforced: Blocked Port {packet[TCP].dport}")
                log_event(src_ip, dst_ip, "TCP", "BLOCKED", 1.0, f"Blocked Port {packet[TCP].dport}", "")
                return

        
        # 8. GEO-BLOCKING CHECK

        is_geo_blocked, country_code = check_geo_block(src_ip)
        if is_geo_blocked:
            msg = f"Geo-Blocking Policy Enforced: {country_code}"
            print(f"\n[BLOCK] {msg} ({src_ip})")
            # Log event
            log_event(src_ip, dst_ip, "IP", "BLOCKED", 1.0, f"Geo-Block: {country_code}", "")
            notify_admin(src_ip, msg)
            return # Stop processing this packet
        
        
        # 9. GLOBAL THREAT INTEL CHECK
       
        if is_global_threat(src_ip):
            msg = "Global Threat Intelligence Match"
            print(f"\n[BLOCK] {msg}: {src_ip}")
            log_event(src_ip, dst_ip, "IP", "BLOCKED", 1.0, "Global Threat Feed", "")
            notify_admin(src_ip, msg)
            return # Block immediately


        # 10. FRIEND'S LOGIC (Rules & Heuristics)
     
        # A1. MALICIOUS C2 CHECK
        if src_ip in MALICIOUS_IPS or dst_ip in MALICIOUS_IPS:
            msg = f"Malicious C2 IP Detected: {src_ip}"
            print(f"\n[BLOCK] {msg}")
            log_event(src_ip, dst_ip, "IP", "BLOCKED", 1.0, "Malicious C2 Blacklist", "")
            notify_admin(src_ip, msg)
            return

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]

            # A2. SUSPICIOUS PORT CHECK (Detects suspicious_port.py)
            if tcp_layer.dport == 9999 or tcp_layer.dport == 6667:
                msg = f"Suspicious Port Usage: {src_ip} -> {tcp_layer.dport}"
                print(f"\n[BLOCK] {msg}")
                log_event(src_ip, dst_ip, "TCP", "BLOCKED", 1.0, "Suspicious Port Usage", "")
                notify_admin(src_ip, msg)
                return
            # Port Scanning (Another Flow-Based check)
            port_scans[src_ip].add(tcp_layer.dport)
            if len(port_scans[src_ip]) > 15:
                print(f"\n[ALERT] Port Scan Detected from {src_ip}")
                log_event(src_ip, dst_ip, "TCP", "ALERT", 0.90, "Port Scan Activity", "")
                port_scans[src_ip].clear()
            
            # 8. LARGE PAYLOAD CHECK (Detects large_payloads.py)

            if len(packet) > 2000:
                msg = f"Abnormal Payload Size: {len(packet)} bytes"
                print(f"\n[BLOCK] {msg}")
                log_event(src_ip, dst_ip, "TCP", "BLOCKED", 1.0, "Large Payload Anomaly", "")
                notify_admin(src_ip, msg)
                return
            
            # 9. DEEP PACKET INSPECTION (DPI)

            if packet.haslayer(Raw):    # Raw is the Scapy layer for payload data
                payload = packet[Raw].load
                is_threat, threat_type, conf = inspect_payload(payload)
                
                if is_threat:
                    msg = f"DPI ALERT: {threat_type} in packet from {src_ip}"
                    print(f"\n[BLOCK] {msg}")
                    # CAPTURE FORENSIC EVIDENCE 
                    pcap_filename = capture_attack_packet(packet, threat_type)

                    # Pass pcap_filename to the logger
                    log_event(src_ip, dst_ip, "TCP", "BLOCKED", conf, threat_type, pcap_filename)
                    
                    notify_admin(src_ip, msg)

                    return # Drop the packet
                

            # 10. DNS SECURITY (Tunneling & Sinkhole)
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                try:
                    # Decode bytes to string (e.g., b'google.com.' -> 'google.com.')
                    qname_bytes = packet[DNS].qd.qname
                    qname = qname_bytes.decode('utf-8')
                    
                    # 10.1 Static Blacklist (Sinkhole)
                    if check_malicious_domain(qname):
                        msg = f"DNS Sinkhole Triggered: {qname}"
                        print(f"\n[BLOCK] {msg}")
                        
                        # 1. Log Event
                        log_event(src_ip, dst_ip, "DNS", "SINKHOLED", 1.0, "Malicious Domain", "")
                        notify_admin(src_ip, msg)
                        
                        # 2. Send Fake Response
                        fake_response = forge_sinkhole_response(packet)
                        send(fake_response, verbose=0)
                        return # Stop processing (we handled it)

                    # 10.2 Tunneling Heuristics (Entropy/Length)
                    is_tunnel, reason = is_dns_tunneling(qname)
                    if is_tunnel:
                        msg = f"DNS Tunneling Detected: {qname} ({reason})"
                        print(f"\n[BLOCK] {msg}")
                        log_event(src_ip, dst_ip, "DNS", "BLOCKED", 0.95, f"Tunneling: {reason}", "")
                        notify_admin(src_ip, msg)
                        return

                except Exception as e:
                    # DNS parsing can sometimes fail on malformed packets
                    pass

            # 11. DDoS CHECK (>50 packets/sec)
            # current_time = time.time()
            # packet_counts[src_ip] = [t for t in packet_counts[src_ip] if current_time - t < 1.0]
            # packet_counts[src_ip].append(current_time)
            
            # if len(packet_counts[src_ip]) > 50:
            #     msg = f"DDoS Flood Detected from {src_ip}"
            #     print(f"\n[BLOCK] 🌊 {msg}")
            #     log_event(src_ip, dst_ip, "TCP", "BLOCKED", 0.99, "DDoS Volume Flood", "")
            #     notify_admin(src_ip, msg)
            #     return

            # # 12. PORT SCAN CHECK (>15 ports/10 sec)
            # port_scans[src_ip].add(tcp_layer.dport)
            # if len(port_scans[src_ip]) > 15:
            #     msg = f"Port Scan Detected from {src_ip}"
            #     print(f"\n[ALERT] 🔍 {msg}")
            #     log_event(src_ip, dst_ip, "TCP", "ALERT", 0.90, "Port Scan Activity", "")
            #     notify_admin(src_ip, msg)
            #     port_scans[src_ip].clear()


        # 11. AI MODEL (Random Forest)   
        if model and packet.haslayer(TCP):
            try:
                # 1. Extract Features
                src_bytes = len(packet)
                protocol = "tcp"
                service = get_service_name(packet[TCP].dport)
                flag = get_flag_name(packet[TCP].flags)

                # 2. Encode Features (Safe Transform)
                def safe_transform(encoder, val):
                    try: return encoder.transform([str(val)])[0]
                    except: return 0 # Default to 0 if unseen

                proto_enc = safe_transform(encoders["protocol_type"], protocol)
                service_enc = safe_transform(encoders["service"], service)
                flag_enc = safe_transform(encoders["flag"], flag)

                # 3. Predict
                features = pd.DataFrame([[src_bytes, proto_enc, service_enc, flag_enc]], 
                                        columns=["src_bytes", "protocol_type", "service", "flag"])
                
                prediction = model.predict(features)[0] # 1=Anomaly, 0=Normal
                confidence = max(model.predict_proba(features)[0])

                # 4. Act
                if prediction == 1 and confidence > 0.80:
                    msg = f"AI Anomaly Critical Threat Detected (Conf: {confidence:.2f})"
                    speak_message(msg)

                    # --- NEW: FEEDBACK CHECK (Override Logic) ---
                    # We pass the same encoded features used by the main model
                    current_features = [src_bytes, proto_enc, service_enc, flag_enc]

                    is_safe_by_feedback = check_feedback_override(current_features, feedback_model)

                    if is_safe_by_feedback:
                        # SOFTEN DETECTION: Log it, but do NOT block
                        print(f"\n[ALLOWED] Block Overridden by Feedback Model ({src_ip})")
                        log_event(src_ip, dst_ip, "TCP", "ALLOWED", 1.0, "Feedback Override", "")
                        return # Skip the block!

                    # Original Blocking Logic
                    msg = f"AI Anomaly Detected (Conf: {confidence:.2f})"
                    print(f"\n[BLOCK] {msg}")
                    log_event(src_ip, dst_ip, "TCP", "BLOCKED", float(confidence), "AI: Zero-Day Anomaly", "")
                    notify_admin(src_ip, msg)
                    
            except Exception as e:
                pass # AI extraction failed, let packet pass

        if src_ip in MALICIOUS_IPS:
            print(f"[BLOCK] Malicious IP: {src_ip}")
            log_event(src_ip, dst_ip, "IP", "BLOCKED", 1.0, "Blacklist", "")
            notify_admin(src_ip, "Blacklisted IP detected")
    

# --- THREAD TARGETS ---

def sniffer_process_target(queue, interface):
    """
    PRODUCER: Runs in a separate CPU Core.
    Does nothing but grab packets and shove them into the queue.
    """

    print(f"[INFO] Sniffer Process Started (PID: {os.getpid()})")
    
    def enqueue_packet(pkt):
        try:
            # We only push essential data to keep the queue fast
            queue.put(pkt)
        except Exception:
            pass
    try:
        if interface:
            sniff(iface=interface, prn=enqueue_packet, store=0)
        else:
            sniff(prn=enqueue_packet, store=0)
    except Exception as e:
        print(f"[CRITICAL] Sniffer Process Crashed: {e}")


def analyzer_thread_target(queue):
    """
    CONSUMER: Runs in the Main Thread.
    Pulls packets from queue and runs AI/Rules.
    """
    print("[INFO] Analyzer Engine Started...")

    while True:
        try:
            # Get packet from queue (Block if empty)
            packet = queue.get()
            # Run the heavy logic (AI, Rules, Zero Trust)
            # This function (process_packet) contains all your security logic
            from src.firewall import process_packet
            process_packet(packet)
             # --- NEW: REAL-TIME TRIGGER ---
            # If the packet queue is empty (processing caught up), 
            # tell the dashboard to refresh immediately.
            if queue.empty():
                socketio.emit('force_update', {'msg': 'Live Traffic: New Logs Available'})
        
        except Exception as e:
            print(f"[ERROR] Analyzer Loop: {e}")


def start_firewall(interface=None):
    """
    [ENHANCEMENT] Parallel Execution Setup
    Launches the separate Process and Threads.
    """
    # Inside heartbeat_loop or a new maintenance loop in firewall.py
    global feedback_model
    feedback_model = load_feedback_model()
    log_system_event("INFO", "Sentinel-X Hybrid Engine Starting...")
    print("\n[INFO] Starting Hybrid Firewall Engine (AI + Rules)...")

    # 1. Start Threat Intel Updater (Background Thread)
    t_intel = threading.Thread(target=start_threat_intel_updater, daemon=True)
    t_intel.start()
    
    # 1. Start the Heartbeat
    t_heart = threading.Thread(target=lambda: [update_heartbeat() or time.sleep(5) for _ in range(1000000)], daemon=True)
    t_heart.start()

    # 2. Analyzer (Consumer) -> THREAD
    # Needs to stay as a thread to access shared resources (DB, WebSockets) easily.
    t_analyzer = threading.Thread(target=analyzer_thread_target, args=(packet_queue,), daemon=True)
    t_analyzer.start()

    # 3. Sniffer (Producer) -> PROCESS
    # Runs on a separate Core to prevent UI lag during DDoS.
    p_sniffer = Process(target=sniffer_process_target, args=(packet_queue, interface), daemon=True)
    p_sniffer.start()

    # Call this once on startup
    refresh_firewall_rules()