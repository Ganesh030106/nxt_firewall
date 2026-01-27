import wmi
import keyboard
import time
import threading
import ctypes
import pythoncom
from src.database import log_event
from src.socket_handler import socketio
from src.voice import speak_message

# Configuration
HUMAN_TYPING_LIMIT_MS = 0.05 
TRIGGER_THRESHOLD = 15        
monitor_active = True
lock_triggered = False

# --- BEHAVIORAL PROFILING CONFIGURATION ---

# The limit of human motor function.
# Humans typically type 1 key every 100ms-300ms.
# 50ms (0.05s) is generally considered the physical limit for sustained typing.
HUMAN_TYPING_LIMIT_MS = 0.05 

# How many "superhuman" keystrokes in a row are required to trigger a lock?
# We set this to 15 to allow for accidental fast double-taps by humans.
TRIGGER_THRESHOLD = 15

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

    print("\n[CRITICAL] 🔌 HID ATTACK DETECTED! INITIATING LOCKDOWN...")
    
    # 1. VISUAL & AUDIO ALERTS (Do this BEFORE locking)
    socketio.emit('force_update', {'msg': 'USB Attack: System Locked'})
    log_event("LOCAL_USB", "HARDWARE", "HID_INJECTION", "LOCKED", 1.0, "Rubber Ducky Attack", "")
    
    speak_message("Physical Breach Detected. Locking System in 3 seconds.")
    
    # 2. DELAY (Give the user time to hear the warning)
    time.sleep(3)
    
    # 3. TRIGGER THE OS API
    # This calls 'LockWorkStation' from user32.dll
    # It is equivalent to pressing Win + L
    success = ctypes.windll.user32.LockWorkStation()
    
    if success:
        print("[INFO] 🔒 System Successfully Locked.")
    else:
        print("[ERROR] Failed to lock workstation.")
    
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
    if event.event_type == 'down':
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
    Uses WMI to detect when a new USB device is plugged in.
    """
    pythoncom.CoInitialize()
    c = wmi.WMI()
    watcher = c.Win32_PnPEntity.watch_for("creation")
    
    print("[INFO] 🔌 USB Sentinel Watching for Hardware Changes...")
    
    while monitor_active:
        try:
            usb_device = watcher()
            name = getattr(usb_device, "Caption", "Unknown Device")
            if "Keyboard" in name or "HID" in name:
                print(f"[WARN] ⚠️ New Input Device Detected: {name}")
        except:
            pass

def start_usb_sentinel():
    print("[INFO] ⌨️ Keystroke Velocity Monitor Active.")
    
    # Remove existing hooks
    try: keyboard.unhook_all()
    except: pass
        
    # Start the Profiling Hook
    keyboard.hook(on_key_event)
    
    # Start Hardware Monitor
    threading.Thread(target=monitor_usb_insertions, daemon=True).start()