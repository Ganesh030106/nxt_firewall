import numpy as np
import pandas as pd
import os
import joblib
from sklearn.preprocessing import MinMaxScaler
from dl_traffic import create_lstm_model, MODEL_PATH, SCALER_PATH

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATASET_PATH = os.path.join(PROJECT_ROOT, "models", "traffic_data.csv")

# We define the column name we WANT to find
TARGET_COLUMN_NAME = "Total Length of Fwd Packets"

def create_sequences(data, seq_length=10):
    X, y = [], []
    for i in range(len(data) - seq_length):
        X.append(data[i:i+seq_length])
        y.append(data[i+seq_length])
    return np.array(X), np.array(y)

def train_real_lstm():
    print(f"--- 🧠 TRAINING LSTM ON REAL DATA ({DATASET_PATH}) ---")

    if not os.path.exists(DATASET_PATH):
        print(f"[ERROR] Dataset not found at {DATASET_PATH}")
        return

    # 1. Load Data
    print("[1/5] Loading CSV...")
    # Read just the header first to clean column names
    df_iter = pd.read_csv(DATASET_PATH, iterator=True, chunksize=1000)
    df_chunk = next(df_iter)
    
    # AUTO-FIX: Strip spaces from column names (Fixes ' Total...' error)
    df_chunk.columns = df_chunk.columns.str.strip()
    
    if TARGET_COLUMN_NAME not in df_chunk.columns:
        print(f"[ERROR] Could not find column '{TARGET_COLUMN_NAME}'.")
        print(f"Available columns: {list(df_chunk.columns)}")
        return

    # 2. Read full data (Only the specific column to save memory)
    # We re-read using the cleaned index logic
    df = pd.read_csv(DATASET_PATH, usecols=lambda x: x.strip() == TARGET_COLUMN_NAME)
    
    # 3. Data Cleaning
    print("[2/5] Cleaning Data...")
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.dropna(inplace=True)
    
    values = df.values.reshape(-1, 1)

    # 4. Normalization
    print("[3/5] Scaling Data...")
    scaler = MinMaxScaler(feature_range=(0, 1))
    scaled_data = scaler.fit_transform(values)
    
    joblib.dump(scaler, SCALER_PATH)

    # 5. Create Sequences
    SEQ_LEN = 10
    X, y = create_sequences(scaled_data, SEQ_LEN)
    
    print(f"[INFO] Training Samples: {len(X)}")

    # 6. Train Model
    print("[4/5] Training LSTM Model (Epochs: 2)...")
    model = create_lstm_model()
    
    model.fit(X, y, epochs=2, batch_size=64, validation_split=0.1)

    # 7. Save
    model.save(MODEL_PATH)
    print(f"[5/5] ✅ SUCCESS: Model saved to {MODEL_PATH}")
    print(f"       ✅ Scaler saved to {SCALER_PATH}")

if __name__ == "__main__":
    train_real_lstm()