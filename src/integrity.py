import os
import hashlib
import json
import time
import threading
import sys
import requests
from src.database import log_system_event

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
BASELINE_FILE = os.path.join(PROJECT_ROOT, "integrity_baseline.json")
ADMIN_API_URL = "http://127.0.0.1:5001/api/alert"

# Critical files to protect (Paths relative to PROJECT_ROOT)
CRITICAL_FILES = [
    "app.py",
    "admin.py",
    os.path.join("src", "firewall.py"),
    os.path.join("src", "database.py"),
    os.path.join("src", "dpi.py"),
    os.path.join("src", "honeypot.py"),
    os.path.join("src", "integrity.py")
]

def calculate_file_hash(filepath):
    """Calculates SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read in chunks to handle large files efficiently
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except FileNotFoundError:
        return None
    except Exception:
        return None

def load_baseline():
    """Loads trusted hashes from JSON."""
    if not os.path.exists(BASELINE_FILE):
        return None
    try:
        with open(BASELINE_FILE, 'r') as f:
            return json.load(f)
    except:
        return None

def generate_baseline():
    """Generates the initial trusted state (Run once or after updates)."""
    baseline = {}
    print("[DEFENSE] 🛡️ Generating Integrity Baseline...")
    for rel_path in CRITICAL_FILES:
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        file_hash = calculate_file_hash(full_path)
        if file_hash:
            baseline[rel_path] = file_hash
    
    with open(BASELINE_FILE, 'w') as f:
        json.dump(baseline, f, indent=4)
    print(f"[DEFENSE] ✅ Baseline saved to {BASELINE_FILE}")

def notify_tamper(file_path):
    """Alerts Admin of modification."""
    msg = f"CRITICAL: System Integrity Compromised! File modified: {file_path}"
    print(f"\n[CRITICAL] 🚨 {msg}")
    log_system_event("CRITICAL", msg)
    try:
        requests.post(ADMIN_API_URL, json={"source": "SYSTEM_DEFENSE", "message": msg}, timeout=1)
    except:
        pass

def integrity_loop():
    """Background thread that checks files every 5 minutes."""
    while True:
        time.sleep(300) # Check every 5 minutes
        
        baseline = load_baseline()
        if not baseline:
            continue # Should not happen if initialized correctly

        for rel_path, trusted_hash in baseline.items():
            full_path = os.path.join(PROJECT_ROOT, rel_path)
            current_hash = calculate_file_hash(full_path)

            if current_hash is None:
                notify_tamper(f"{rel_path} (File Deleted/Missing)")
            elif current_hash != trusted_hash:
                notify_tamper(f"{rel_path} (Hash Mismatch - Potential Malware)")

def start_integrity_monitor():
    """Initializes the self-defense module."""
    # 1. Check if baseline exists. If not, assume current state is clean and generate it.
    if not os.path.exists(BASELINE_FILE):
        generate_baseline()
    
    # 2. Perform immediate startup check
    print("[INFO] Verifying System Integrity...")
    baseline = load_baseline()
    clean = True
    for rel_path, trusted_hash in baseline.items():
        full_path = os.path.join(PROJECT_ROOT, rel_path)
        if calculate_file_hash(full_path) != trusted_hash:
            print(f"[CRITICAL] ❌ STARTUP INTEGRITY CHECK FAILED: {rel_path}")
            clean = False
    
    if clean:
        print("[INFO] ✅ System Integrity Verified.")
    else:
        print("[WARN] ⚠️ System files have been modified since last baseline!")

    # 3. Start Background Monitor
    t = threading.Thread(target=integrity_loop, daemon=True)
    t.start()