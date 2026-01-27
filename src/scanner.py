"""Vulnerability Scanner Module

Provides proactive self-assessment capabilities using Nmap.
Scans localhost for open ports and identifies security vulnerabilities.

Features:
- Automated vulnerability detection
- Risk-based contextualization
- Daily scheduled scans
- Voice alerts for critical findings
- Dashboard integration

Requirements:
- Nmap must be installed (https://nmap.org)
"""

import nmap
import threading
import time
import socket
import os
import logging

# --- INTERNAL MODULE IMPORTS ---
from src.database import log_event
from src.socket_handler import socketio
from src.voice import speak_message

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION: RISK KNOWLEDGE BASE ---
# Contextualizes raw ports into real-world security risks
RISKY_PORTS = {
    445:  "SMB (Risk: EternalBlue/Ransomware). DISABLE IMMEDIATELY.",
    3389: "RDP (Risk: BlueKeep/Brute Force). Use VPN instead.",
    23:   "Telnet (Risk: Unencrypted Traffic). Use SSH.",
    21:   "FTP (Risk: Cleartext Password). Use SFTP.",
    80:   "HTTP (Risk: Unencrypted Web). Ensure HTTPS is used.",
    4444: "Metasploit Listener (High Risk). Check for Backdoors.",
    2323: "IoT Telnet (Mirai Botnet Target).",
    135:  "Microsoft RPC (Can be exploited if unpatched).",
    139:  "NetBIOS (Information leak risk).",
    1433: "MS-SQL (Should not be exposed to internet).",
    3306: "MySQL (Should not be exposed to internet).",
    5432: "PostgreSQL (Should not be exposed to internet).",
}

# Scan configuration
SCAN_INTERVAL = 86400  # 24 Hours (daily audit)
NMAP_ARGUMENTS = '-T4 -F'  # Fast timing, top 100 ports
MAX_RETRIES = 3
RETRY_DELAY = 5  # seconds


def get_local_ip():
    """
    Determines the local IP address for self-scanning.
    
    Returns:
        str: Local IP address or '127.0.0.1' if detection fails
    """
    try:
        # Connect to external DNS to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        logger.info(f"Detected local IP: {local_ip}")
        return local_ip
    except Exception as e:
        logger.warning(f"Failed to detect local IP: {e}, using 127.0.0.1")
        return "127.0.0.1"

def perform_vulnerability_scan():
    """
    Executes comprehensive vulnerability scan on localhost.
    
    Performs Nmap scan to identify open ports and assess security posture.
    Provides risk contextualization for discovered vulnerabilities.
    
    Workflow:
    1. Identify local IP address
    2. Execute Nmap scan (-T4 fast, -F top 100 ports)
    3. Analyze results against risk knowledge base
    4. Generate alerts for critical findings
    5. Log results to database
    """
    target_ip = get_local_ip()
    
    logger.info(f"Starting vulnerability scan on {target_ip}")
    print(f"\n[SCANNER] 🏥 Starting Proactive Vulnerability Scan on {target_ip}...")
    
    # Notify dashboard
    try:
        socketio.emit('force_update', {'msg': 'Running Daily Vulnerability Scan...'})
    except Exception as e:
        logger.debug(f"Failed to emit scan start notification: {e}")

    retry_count = 0
    while retry_count < MAX_RETRIES:
        try:
            nm = nmap.PortScanner()
            
            # Execute scan
            logger.debug(f"Executing: nmap {NMAP_ARGUMENTS} {target_ip}")
            nm.scan(target_ip, arguments=NMAP_ARGUMENTS)
            
            vulnerabilities_found = 0
            ports_scanned = 0
            
            for host in nm.all_hosts():
                logger.info(f"Processing scan results for {host} ({nm[host].hostname()})")
                print(f"[SCANNER] Report for {host} ({nm[host].hostname()})")
                
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    
                    for port in ports:
                        ports_scanned += 1
                        state = nm[host][proto][port]['state']
                        
                        if state == 'open':
                            service = nm[host][proto][port]['name']
                            
                            # Check if port has known security risk
                            if port in RISKY_PORTS:
                                vulnerabilities_found += 1
                                risk_context = RISKY_PORTS[port]
                                
                                msg = f"VULNERABILITY FOUND: Port {port} ({service}) is OPEN."
                                logger.warning(msg)
                                print(f"[CRITICAL] ❌ {msg}")
                                print(f"            ↳ ADVICE: {risk_context}")
                                
                                # Voice alert for critical vulnerabilities
                                try:
                                    speak_message(f"Security Warning. Port {port} is open. {risk_context}")
                                except Exception as e:
                                    logger.debug(f"Voice alert failed: {e}")
                                
                                # Log to dashboard as warning
                                try:
                                    # [CORRECTION] Fix the arguments to match src/database.py definition
                                    log_event(
                                        "127.0.0.1",           # src_ip (Localhost)
                                        "NETWORK_SCAN",        # dst_ip (Target)
                                        "TCP",                 # protocol
                                        "WARNING",             # action
                                        1.0,                   # confidence
                                        f"Vulnerability: Port {port} OPEN", # reason
                                        risk_context           # payload (The advice)
                                    )
                                except Exception as e:
                                    logger.error(f"Failed to log vulnerability: {e}")
                            else:
                                # Standard log for non-risky open ports
                                logger.info(f"Open port {port} ({service}) - Status: OK")
                                print(f"[INFO] ℹ️ Open Port: {port} ({service}) - Status: OK")

            # Summary
            summary_msg = (f"Scan complete: {ports_scanned} ports checked, "
                          f"{vulnerabilities_found} vulnerabilities found")
            logger.info(summary_msg)
            print(f"[SCANNER] ✅ {summary_msg}\n")
            
            # Notify dashboard of completion
            try:
                socketio.emit('force_update', {
                    'msg': f'Vulnerability Scan Complete: {vulnerabilities_found} issues found'
                })
            except Exception as e:
                logger.debug(f"Failed to emit scan complete notification: {e}")
            
            return  # Success, exit function

        except nmap.PortScannerError as e:
            logger.error(f"Nmap not found or error executing: {e}")
            print("[ERROR] Nmap not found. Please install Nmap from https://nmap.org")
            return  # Can't proceed without Nmap
            
        except Exception as e:
            retry_count += 1
            logger.error(f"Scan failed (attempt {retry_count}/{MAX_RETRIES}): {e}")
            print(f"[ERROR] Scan failed (attempt {retry_count}/{MAX_RETRIES}): {e}")
            
            if retry_count < MAX_RETRIES:
                logger.info(f"Retrying in {RETRY_DELAY} seconds...")
                time.sleep(RETRY_DELAY)
            else:
                logger.error("Max retries exceeded, scan aborted")
                print("[ERROR] Max retries exceeded, vulnerability scan aborted")

def start_vulnerability_scanner():
    """
    Scheduled Loop: Runs the audit every 24 hours.
    """
    print("[INFO] 🏥 Proactive Vulnerability Scanner Online.")
    while True:
        perform_vulnerability_scan()
        # Sleep for 24 hours before next scan
        time.sleep(SCAN_INTERVAL)