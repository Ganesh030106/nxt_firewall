#run_all.py

#imports
import os
import sys
import time
import subprocess

# Detect the current directory to locate attack scripts reliably
ATTACK_DIR = os.path.dirname(os.path.abspath(__file__))

# List of available attack scripts
ATTACKS = {
    "1": ("DDoS / Flood Attack", "fastflood.py"),
    "2": ("Ransomware Simulation", "ransomware_sim.py"),
    "3": ("SQL Injection (DPI Test)", "test_dpi.py"),
    "4": ("Honeypot Trap Connection", "test_honeypot.py"),
    "5": ("Large Payload Anomaly", "large_payloads.py"),
    "6": ("Suspicious Port Beaconing", "suspicious_port.py"),
    "7": ("Geo-Blocking Test", "test_geo.py"),
    "8": ("DNS Tunneling Test", "test_dns.py"),
    "9": ("DNS Sinkhole Test", "test_sinkhole.py"),
    "10": ("Threat Intelligence Test", "test_threat_intel.py"),
    "11": ("Fake Attack Log Injection", "fake_attack_logs.py"),
    # "12": ("ARP Poisoning Attack", "arp_attack.py"),
    "12": ("Malware Dropper Simulation", "attack_malware.py"),
    "13": ("Rubber Ducky Simulation", "attack_rubber.py"),
}

# Function to run a single attack script
def run_script(filename):
    """Executes a single python script."""
    filepath = os.path.join(ATTACK_DIR, filename)
    if not os.path.exists(filepath):
        print(f"[ERROR] Script not found: {filename}")
        return

    print(f"\n[🚀] Launching {filename}...")
    try:
        # Uses the same python interpreter running this script
        subprocess.run([sys.executable, filepath], check=True)
        print(f"[✅] Finished {filename}\n")
    except subprocess.CalledProcessError as e:
        print(f"[❌] Error running {filename}: {e}")
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")

# Function to run all attacks in sequence
def run_all_sequence():
    """Runs all attacks sequentially with a delay."""
    print("\n[⚠] WARNING: This will run ALL simulations. Dashboard will be flooded!")
    print("[⚠] Press CTRL+C to cancel anytime.\n")
    time.sleep(2)

    for key, (name, filename) in ATTACKS.items():
        print(f"--- STEP {key}: {name} ---")
        run_script(filename)
        print("[⏳] Cooling down for 3 seconds...")
        time.sleep(3)
    
    print("\n[🎉] Full Stress Test Complete.")

# Main Menu
def main_menu():
    while True:
        print("="*40)
        print(" ⚔️  SENTINEL-X ATTACK CONSOLE")
        print("="*40)
        for key, (name, _) in ATTACKS.items():
            print(f" {key}. {name}")
        print("-" * 40)
        print(" A. 🔥 RUN ALL (Full Stress Test)")
        print(" Q. 🚪 Quit")
        print("="*40)

        # Get user choice
        choice = input("Select an option: ").strip().upper()

        # Handle user choice
        if choice == 'Q':
            print("Exiting...")
            break
        elif choice == 'A':
            run_all_sequence()
            input("\nPress Enter to return to menu...")
        elif choice in ATTACKS:
            name, filename = ATTACKS[choice]
            print(f"\n[Selected]: {name}")
            run_script(filename)
            input("Press Enter to continue...")
        else:
            print("[!] Invalid selection.")

#--- ENTRY POINT ---
if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n[!] Exiting...")