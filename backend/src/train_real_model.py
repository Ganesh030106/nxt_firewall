# src/train_real_model.py

import csv
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os

# Define paths relative to this script
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
CSV_PATH = os.path.join(PROJECT_ROOT, "models", "nsl_kdd_train.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "real_firewall_brain.pkl")

# Step 1: Load Dataset
print("--- 🚂 Training Real-Time Firewall Detection Model ---")
print("Step 1: Loading the Dataset...")
# NSL-KDD has 43 columns. We define them manually because the file often has no headers.
columns = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label","difficulty"]

# Read the CSV
try:
    df = pd.read_csv(CSV_PATH, header=None, names=columns)
    print(f"Data Loaded: {len(df)} rows found.")
except FileNotFoundError:
    print(f"ERROR: Could not find dataset at {CSV_PATH}")
    exit()

# Step 2: Feature Selection
# We only keep features that Scapy can see in live real-time traffic
print("Step 2: Selecting Real-Time Features...")
selected_features = ["src_bytes", "protocol_type", "service", "flag"]

# --- FIX: Added .copy() here to prevent SettingWithCopyWarning ---
X = df[selected_features].copy()
y = df["label"]

# Step 3: Encoding (Converting Text -> Numbers)
encoders = {}
for col in ["protocol_type", "service", "flag"]:
    le = LabelEncoder()
    # Fit the encoder on the column
    X[col] = le.fit_transform(X[col].astype(str))
    # Save it for later
    encoders[col] = le

# Convert Labels: 'normal' -> 0, anything else (neptune, satan, etc.) -> 1
y = y.apply(lambda x: 0 if x == "normal" else 1)

# Step 4: Train the Brain
print("Step 3: Training Random Forest (This might take 10 seconds)...")
clf = RandomForestClassifier(n_estimators=100, random_state=42)
clf.fit(X, y)

# Step 5: Save
print("Step 4: Saving Model and Encoders...")
payload = {
    "model": clf,
    "encoders": encoders
}
joblib.dump(payload, MODEL_PATH)
print(f"✅ SUCCESS: '{MODEL_PATH}' is ready!")