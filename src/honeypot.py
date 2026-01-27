"""Honeypot Trap Module

Operates a deceptive service on port 2323 to detect and log unauthorized access attempts.
Provides early warning system for network reconnaissance and attack attempts.

Features:
- Fake Telnet service to attract attackers
- Automatic logging and alerting
- Connection rate limiting per IP
- Graceful error handling and recovery
"""

import socket
import threading
import requests
import time
import logging
from collections import defaultdict, deque
from src.database import log_event

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
HONEYPOT_PORT = 2323  # Mimics Telnet (23) without requiring root privileges
ADMIN_API_URL = "http://127.0.0.1:5001/api/alert"
FAKE_BANNER = b"Welcome to Security System\r\nLogin: "
MAX_CONNECTIONS_PER_IP = 5  # Rate limit per IP
CONNECTION_TIMEOUT = 10  # seconds
CLEANUP_INTERVAL = 300  # Clean rate limit cache every 5 minutes

# --- STATE TRACKING ---
connection_counts = defaultdict(int)
recent_connections = defaultdict(lambda: deque(maxlen=10))
last_cleanup = time.time()
cleanup_lock = threading.Lock()


def notify_admin(src_ip, msg):
    """
    Sends immediate alert to Admin Console.
    
    Args:
        src_ip (str): Source IP address of the attack
        msg (str): Alert message
    """
    try:
        response = requests.post(
            ADMIN_API_URL,
            json={"source": src_ip, "message": msg},
            timeout=1
        )
        if response.status_code == 200:
            logger.debug(f"Admin notified about {src_ip}")
    except requests.RequestException as e:
        logger.debug(f"Admin notification failed: {e}")
    except Exception as e:
        logger.error(f"Unexpected error notifying admin: {e}")


def cleanup_rate_limits():
    """
    Periodically cleans up old connection tracking data.
    Prevents memory growth from connection counters.
    """
    global last_cleanup
    
    current_time = time.time()
    if current_time - last_cleanup < CLEANUP_INTERVAL:
        return
    
    with cleanup_lock:
        # Clear counters for IPs with no recent activity
        expired_ips = [
            ip for ip, last_time in recent_connections.items()
            if last_time and (current_time - last_time[-1]) > CLEANUP_INTERVAL
        ]
        
        for ip in expired_ips:
            if ip in connection_counts:
                del connection_counts[ip]
            if ip in recent_connections:
                del recent_connections[ip]
        
        if expired_ips:
            logger.debug(f"Cleaned up {len(expired_ips)} inactive IP entries")
        
        last_cleanup = current_time


def check_rate_limit(src_ip):
    """
    Checks if IP has exceeded connection rate limit.
    
    Args:
        src_ip (str): Source IP address
        
    Returns:
        bool: True if rate limit exceeded, False otherwise
    """
    current_time = time.time()
    recent_connections[src_ip].append(current_time)
    
    # Count connections in last minute
    recent_window = [t for t in recent_connections[src_ip] if current_time - t < 60]
    
    if len(recent_window) > MAX_CONNECTIONS_PER_IP:
        logger.warning(f"Rate limit exceeded for {src_ip}: {len(recent_window)} connections")
        return True
    
    return False


def handle_connection(client_socket, client_address):
    """
    Handles incoming honeypot connection.
    
    Logs the attempt, sends fake banner, and gracefully closes connection.
    Implements rate limiting to prevent resource exhaustion.
    
    Args:
        client_socket: Socket object for client connection
        client_address: Tuple of (ip, port) for client
    """
    src_ip = client_address[0]
    src_port = client_address[1]
    dst_ip = "127.0.0.1"  # Localhost
    
    try:
        # Rate limiting check
        if check_rate_limit(src_ip):
            logger.info(f"Dropping honeypot connection from {src_ip} due to rate limit")
            client_socket.close()
            return
        
        # Periodic cleanup
        cleanup_rate_limits()
        
        logger.info(f"Honeypot triggered by {src_ip}:{src_port}")
        print(f"\n[BLOCK] 🍯 HONEYPOT TRIGGERED by {src_ip}")
        
        # 1. Log the block to main dashboard
        log_event(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="TCP",
            action="BLOCKED",
            confidence=1.0,
            reason=f"Honeypot Trap (Port {HONEYPOT_PORT})",
            details=f"Connection from {src_ip}:{src_port}"
        )
        
        # 2. Alert admin console
        notify_admin(
            src_ip,
            f"Honeypot Trap Triggered on Port {HONEYPOT_PORT} from {src_ip}"
        )
        
        # 3. Send deceptive banner to confuse attacker
        try:
            client_socket.settimeout(CONNECTION_TIMEOUT)
            client_socket.send(FAKE_BANNER)
            
            # Wait briefly for input (optional - helps with reconnaissance detection)
            try:
                data = client_socket.recv(1024)
                if data:
                    logger.info(f"Honeypot received data from {src_ip}: {data[:50]}")
            except socket.timeout:
                pass
            
            # Send fake error message
            client_socket.send(b"Login incorrect.\r\n")
            
        except socket.error as e:
            logger.debug(f"Socket error sending banner to {src_ip}: {e}")
        
    except Exception as e:
        logger.error(f"Error handling honeypot connection from {src_ip}: {e}")
    
    finally:
        # Always close the socket
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except:
            pass
        try:
            client_socket.close()
        except:
            pass


def start_honeypot():
    """
    Starts the honeypot listener service.
    
    Listens for incoming connections on HONEYPOT_PORT and spawns
    handler threads for each connection attempt.
    """
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind(("0.0.0.0", HONEYPOT_PORT))
        server.listen(5)
        
        logger.info(f"Honeypot service started on port {HONEYPOT_PORT}")
        print(f"[INFO] Honeypot Trap Active on Port {HONEYPOT_PORT}...")
        
        while True:
            try:
                client, addr = server.accept()
                
                # Spawn handler thread for each connection
                handler_thread = threading.Thread(
                    target=handle_connection,
                    args=(client, addr),
                    daemon=True,
                    name=f"Honeypot-{addr[0]}"
                )
                handler_thread.start()
                
            except socket.error as e:
                logger.error(f"Socket error accepting connection: {e}")
                time.sleep(0.1)  # Brief pause to prevent tight loop on error
            except Exception as e:
                logger.error(f"Unexpected error in honeypot accept loop: {e}")
                time.sleep(1)

    except OSError as e:
        if hasattr(e, 'winerror') and e.winerror == 10048:
            logger.warning(f"Honeypot port {HONEYPOT_PORT} already in use")
            print(f"[WARN] ⚠️ Honeypot Port {HONEYPOT_PORT} is already in use. Skipping module start.")
        else:
            logger.critical(f"Honeypot failed to start: {e}")
            print(f"[CRITICAL] Honeypot failed to start: {e}")
    except Exception as e:
        logger.critical(f"Unexpected error starting honeypot: {e}")
        print(f"[CRITICAL] Unexpected honeypot error: {e}")
    finally:
        try:
            server.close()
        except:
            pass