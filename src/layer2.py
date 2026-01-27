import os
import time
import shutil
import yara
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.database import log_event
from src.socket_handler import socketio
from src.voice import speak_message

# CONFIGURATION
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCH_DIR = os.path.join(BASE_DIR, "Simulated_Downloads")
QUARANTINE_DIR = os.path.join(BASE_DIR, "Quarantine_Vault")
RULES_PATH = os.path.join(BASE_DIR, "models", "malware_rules.yar")

# Ensure directories exist
os.makedirs(WATCH_DIR, exist_ok=True)
os.makedirs(QUARANTINE_DIR, exist_ok=True)

class MalwareHandler(FileSystemEventHandler):
    def __init__(self, rules):
        self.rules = rules

    def on_created(self, event):
        if event.is_directory: return
        self.scan_file(event.src_path)

    def on_modified(self, event):
        if event.is_directory: return
        self.scan_file(event.src_path)

    def scan_file(self, filepath):
        # Wait briefly for file write to complete
        time.sleep(0.5)
        
        try:
            print(f"[SCAN] 🔍 Analyzing file: {os.path.basename(filepath)}")
            matches = self.rules.match(filepath)
            
            if matches:
                rule_name = matches[0].rule
                print(f"[CRITICAL] 🦠 MALWARE DETECTED: {rule_name}")
                self.quarantine_file(filepath, rule_name)
        except Exception as e:
            # print(f"[ERROR] Scan failed: {e}")
            pass

    def quarantine_file(self, filepath, threat_name):
        try:
            filename = os.path.basename(filepath)
            dest_path = os.path.join(QUARANTINE_DIR, filename)
            
            # Move file to quarantine
            shutil.move(filepath, dest_path)
            
            # 1. Voice Alert
            speak_message(f"Virus Detected. {threat_name}. File Quarantined.")
            
            # 2. Log to Dashboard
            log_event("LOCAL_SYSTEM", "FILESYSTEM", "MALWARE", "QUARANTINED", 1.0, f"YARA: {threat_name}", "")
            
            # 3. WebSocket Alert
            socketio.emit('force_update', {'msg': f'Malware Quarantined: {threat_name}'})
            
            print(f"[INFO] 🛡️ File moved to Quarantine Vault: {dest_path}")
            
        except Exception as e:
            print(f"[ERROR] Quarantine failed: {e}")

def start_malware_monitor():
    print(f"[INFO] 🧬 YARA Malware Scanner Loaded.")
    print(f"[INFO] 📂 Monitoring Folder: {WATCH_DIR}")
    
    try:
        rules = yara.compile(filepath=RULES_PATH)
        event_handler = MalwareHandler(rules)
        observer = Observer()
        observer.schedule(event_handler, WATCH_DIR, recursive=False)
        observer.start()
        
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
        observer.join()
        
    except Exception as e:
        print(f"[ERROR] Failed to start YARA Scanner: {e}")