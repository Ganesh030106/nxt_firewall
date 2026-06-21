#ransomware_sim.py

#imports
import os
import time


# 1. Locate the Target "Vault" Folder
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
TARGET_FOLDER = os.path.join(PROJECT_ROOT, "sentinel_protected")

# 3. Simulate Ransomware Activity
print(f"--- ⚠️  STARTING RANSOMWARE SIMULATION ---")
print(f"Target Vault: {TARGET_FOLDER}")
print(f"Action: Rapidly creating 20 encrypted dummy files...\n")

# Ensure folder exists (just in case)
if not os.path.exists(TARGET_FOLDER):
    try:
        os.makedirs(TARGET_FOLDER)
    except Exception as e:
        print(f"[!] Error: Could not find or create folder: {e}")
        exit()

try:
    # 2. The Attack Loop
    # Create 20 files in less than 2 seconds to trigger the "15 files / 5 sec" rule.
    for i in range(20):
        filename = f"encrypted_data_{i}.txt"
        filepath = os.path.join(TARGET_FOLDER, filename)
        
        with open(filepath, "w") as f:
            f.write("YOUR_FILES_ARE_ENCRYPTED_BY_SENTINEL_TEST")
            
        print(f"[>] Encrypting: {filename}")
        time.sleep(0.05) # Very fast writes

    print("\n[✔] Simulation Complete.")
    print("Check your Main Terminal & Dashboard for 'CRITICAL RANSOMWARE ALERT'!")

except Exception as e:
    print(f"\n[!] Attack failed: {e}")