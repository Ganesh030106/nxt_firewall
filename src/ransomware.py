"""Ransomware Detection Module

Monitors file system for rapid file modification patterns indicating ransomware activity.
Uses watchdog library to detect suspicious encryption behavior in protected directories.

Detection Method:
- Monitors specific protected folder for file changes
- Tracks modification velocity (files changed per time window)
- Triggers alert when threshold exceeded

Configuration:
- Protected folder: senitinel_protected/
- Threshold: 15 files modified within 5 seconds
"""

import time
import os
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from src.database import log_system_event, log_event

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
PROTECTED_FOLDER_NAME = "senitinel_protected"
MODIFICATION_THRESHOLD = 15  # Max files allowed to change
TIME_WINDOW = 5              # Time window in seconds
ALERT_COOLDOWN = 10          # Cooldown period after alert (seconds)

# Determine protected folder path
PROTECTED_FOLDER_PATH = os.path.join(os.getcwd(), PROTECTED_FOLDER_NAME)

# Ensure the folder exists
if not os.path.exists(PROTECTED_FOLDER_PATH):
    try:
        os.makedirs(PROTECTED_FOLDER_PATH)
        logger.info(f"Created protected folder at: {PROTECTED_FOLDER_PATH}")
        print(f"[INFO] Created protected folder at: {PROTECTED_FOLDER_PATH}")
    except OSError as e:
        logger.error(f"Could not create protected folder: {e}")
        print(f"[ERROR] Could not create protected folder: {e}")


class RansomwareHandler(FileSystemEventHandler):
    """File system event handler for ransomware detection."""
    
    def __init__(self):
        """Initialize handler with tracking state."""
        self.modification_count = 0
        self.start_time = time.time()
        self.threshold = MODIFICATION_THRESHOLD
        self.time_window = TIME_WINDOW
        self.last_alert_time = 0
        self.alert_cooldown = ALERT_COOLDOWN
        
        logger.info(f"Ransomware handler initialized (threshold={self.threshold}, "
                   f"window={self.time_window}s)")

    def on_modified(self, event):
        """
        Handle file modification events.
        
        Args:
            event: File system event from watchdog
        """
        # Ignore directory modifications
        if event.is_directory:
            return

        # Verify file is in protected folder
        if PROTECTED_FOLDER_NAME not in event.src_path:
            return

        current_time = time.time()
        
        # Reset counter if time window has passed
        if current_time - self.start_time > self.time_window:
            self.modification_count = 0
            self.start_time = current_time

        self.modification_count += 1
        
        logger.debug(f"File modified: {os.path.basename(event.src_path)} "
                    f"(count: {self.modification_count}/{self.threshold})")

        # Check if threshold exceeded and cooldown expired
        if (self.modification_count > self.threshold and
            current_time - self.last_alert_time > self.alert_cooldown):
            
            self._trigger_alert(current_time)

    def _trigger_alert(self, current_time):
        """
        Trigger ransomware alert and log to system.
        
        Args:
            current_time (float): Current timestamp
        """
        alert_msg = (f"RANSOMWARE ALERT: {self.modification_count} files modified "
                    f"rapidly in protected folder!")
        
        logger.critical(alert_msg)
        print(f"[CRITICAL] {alert_msg}")
        
        # Log to database
        try:
            log_event(
                src_ip="LOCALHOST",
                dst_ip="FILESYSTEM",
                protocol="FILE",
                action="ALERT",
                confidence=1.0,
                reason="Rapid Encryption Detected",
                details=f"{self.modification_count} files in {self.time_window}s"
            )
            log_system_event("CRITICAL", alert_msg)
            logger.info("Ransomware alert logged to database")
        except Exception as e:
            logger.error(f"Failed to log ransomware alert: {e}")
        
        # Update alert state
        self.last_alert_time = current_time
        self.modification_count = 0
        
        # Brief pause to prevent alert flooding
        time.sleep(2)


def start_ransomware_monitor(path_ignored=None):
    """
    Starts the ransomware file system monitor.
    
    Args:
        path_ignored: Ignored parameter (kept for backward compatibility)
        
    Returns:
        Observer: Watchdog observer instance
    """ 
    # Always use the designated protected folder
    target_path = PROTECTED_FOLDER_PATH
    
    logger.info(f"Starting ransomware monitor on: {target_path}")
    print(f"[INFO] Ransomware Monitor: Watching ONLY '{target_path}'")
    
    try:
        event_handler = RansomwareHandler()
        observer = Observer()
        observer.schedule(event_handler, target_path, recursive=True)
        observer.start()
        
        # Log successful startup
        try:
            log_system_event("INFO", f"Ransomware Monitor started on: {target_path}")
        except Exception as e:
            logger.error(f"Failed to log ransomware monitor startup: {e}")
        
        logger.info("Ransomware monitor started successfully")
        return observer
        
    except Exception as e:
        logger.error(f"Failed to start ransomware monitor: {e}")
        print(f"[ERROR] Failed to start ransomware monitor: {e}")
        raise