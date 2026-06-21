import sys
import os

# Fix import path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanner import perform_vulnerability_scan

print("--- 🏥 MANUAL VULNERABILITY AUDIT ---")
print("Triggering Sentinel-X Self-Diagnosis...")

perform_vulnerability_scan()