try:
    import wmi
except ImportError:
    wmi = None

try:
    import keyboard
except ImportError:
    keyboard = None

try:
    import pythoncom
except ImportError:
    pythoncom = None

import time
import threading
import ctypes
from src.database import log_event
from src.socket_handler import socketio
from src.voice import speak_message

# Configuration
HUMAN_TYPING_LIMIT_MS = 0.05 
TRIGGER_THRESHOLD = 15        
monitor_active = True
lock_triggered = False

# State Variables
last_key_time = 0
fast_sequence_count = 0
monitor_active = True
lock_triggered = False # Prevent double locking

def lock_workstation():
    """Executes the defense mechanism sequence."""
    global lock_triggered
    if lock_triggered: return
    lock_triggered = True

    print("\n[CRITICAL] HID ATTACK DETECTED! INITIATING LOCKDOWN...")
    
    # 1. VISUAL & AUDIO ALERTS (Do this BEFORE locking)
    socketio.emit('force_update', {'msg': 'USB Attack: System Locked'})
    log_event("LOCAL_USB", "HARDWARE", "HID_INJECTION", "LOCKED", 1.0, "Rubber Ducky Attack", "")
    
    speak_message("Physical Breach Detected. Locking System in 3 seconds.")
    
    # 2. DELAY (Give the user time to hear the warning)
    time.sleep(3)
    
    # 3. TRIGGER THE OS API (Windows only)
    if hasattr(ctypes, 'windll') and hasattr(ctypes.windll, 'user32'):
        try:
            success = ctypes.windll.user32.LockWorkStation()
            if success:
                print("[INFO] System Successfully Locked.")
            else:
                print("[ERROR] Failed to lock workstation.")
        except Exception as e:
            print(f"[ERROR] Failed to execute Windows Lock: {e}")
    else:
        print("[WARN] System Lock simulation: platform does not support user32.dll LockWorkStation.")
    
    # Reset state after lock
    time.sleep(5)
    lock_triggered = False

def on_key_event(event):
    """
    Human vs. Machine Behavioral Profiling
    Analyzes every keystroke for superhuman speed.
    """
    global last_key_time, fast_sequence_count
    
    # Only process 'down' events (presses)
    if getattr(event, 'event_type', None) == 'down':
        current_time = time.time()
        time_diff = current_time - last_key_time
        
        # If the key was pressed faster than physically possible
        if time_diff < HUMAN_TYPING_LIMIT_MS:
            fast_sequence_count += 1
        else:
            # Reset count if typing returns to human speed
            fast_sequence_count = 0
            
        last_key_time = current_time
        
        # TRIGGER DEFENSE
        if fast_sequence_count > TRIGGER_THRESHOLD:
            fast_sequence_count = 0
            # Run lock in a separate thread so it doesn't block the keyboard hook
            threading.Thread(target=lock_workstation, daemon=True).start()

def monitor_usb_insertions():
    """
    Uses WMI to detect when a new USB device is plugged in (Windows only).
    """
    if not wmi or not pythoncom:
        return
    try:
        pythoncom.CoInitialize()
        c = wmi.WMI()
        watcher = c.Win32_PnPEntity.watch_for("creation")
        
        print("[INFO] USB Sentinel Watching for Hardware Changes...")
        
        while monitor_active:
            try:
                usb_device = watcher()
                name = getattr(usb_device, "Caption", "Unknown Device")
                if "Keyboard" in name or "HID" in name:
                    print(f"[WARN] New Input Device Detected: {name}")
            except:
                pass
    except Exception as e:
        print(f"[ERROR] USB Monitor exception: {e}")

def start_usb_sentinel():
    if not keyboard:
        print("[WARN] USB Sentinel keystroke monitor disabled: missing 'keyboard' module.")
        return
        
    print("[INFO] Keystroke Velocity Monitor Active.")
    
    # Remove existing hooks
    try: keyboard.unhook_all()
    except: pass
        
    # Start the Profiling Hook
    try:
        keyboard.hook(on_key_event)
    except Exception as e:
        print(f"[WARN] Failed to hook keyboard (requires root/admin permissions): {e}")
    
    # Start Hardware Monitor
    if wmi and pythoncom:
        threading.Thread(target=monitor_usb_insertions, daemon=True).start()
    else:
        print("[WARN] USB insertion monitoring disabled: missing WMI dependencies.")