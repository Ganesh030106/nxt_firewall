import numpy as np
import os
import joblib
from collections import deque
from sklearn.preprocessing import MinMaxScaler

# --- ROBUST IMPORT BLOCK FOR KERAS 3 ---
try:
    # Try importing Keras directly (Standard for Keras 3+)
    import keras
    from keras.models import Sequential, load_model
    from keras.layers import LSTM, Dense, Dropout, Input
    TF_AVAILABLE = True
except ImportError:
    try:
        # Fallback to TensorFlow-bundled Keras (Legacy)
        import tensorflow as tf
        from tensorflow.keras.models import Sequential, load_model
        from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
        TF_AVAILABLE = True
    except ImportError:
        print("[WARN] TensorFlow/Keras not installed. Deep Learning disabled.")
        TF_AVAILABLE = False
# ---------------------------------------

# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "traffic_lstm.h5")
SCALER_PATH = os.path.join(PROJECT_ROOT, "models", "traffic_scaler.pkl")

# Store the last 10 traffic volume data points for prediction
traffic_buffer = deque(maxlen=10)

def clean_buffer():
    """Remove any numpy objects from buffer and convert to Python floats."""
    cleaned = deque(maxlen=10)
    for val in traffic_buffer:
        try:
            if isinstance(val, np.ndarray):
                cleaned.append(float(np.asarray(val).item()))
            else:
                cleaned.append(float(val))
        except:
            pass
    return cleaned

def create_lstm_model():
    """Creates a simple LSTM model for time-series forecasting."""
    model = Sequential([
        # FIXED: Explicit Input Layer to silence warnings
        Input(shape=(10, 1)),
        LSTM(50, return_sequences=True),
        Dropout(0.2),
        LSTM(50, return_sequences=False),
        Dropout(0.2),
        Dense(1)
    ])
    model.compile(optimizer='adam', loss='mean_squared_error')
    return model

def load_traffic_model():
    """Loads the LSTM model from disk or initializes a new one."""
    if not TF_AVAILABLE: return None

    if os.path.exists(MODEL_PATH):
        try:
            return load_model(MODEL_PATH)
        except:
            return None
    else:
        # Create dummy model if none exists (Auto-init)
        print("[INFO] Initializing new LSTM Traffic Model...")
        model = create_lstm_model()
        # Dummy train to initialize structure/weights
        X_dummy = np.random.rand(1, 10, 1)
        y_dummy = np.random.rand(1, 1)
        model.fit(X_dummy, y_dummy, verbose=0)
        model.save(MODEL_PATH)
        return model

# --- GLOBAL OBJECTS ---
lstm_model = load_traffic_model()

# Load the Scaler (Must match the one used in training)
traffic_scaler = None
if os.path.exists(SCALER_PATH):
    try:
        traffic_scaler = joblib.load(SCALER_PATH)
        print("[INFO] Traffic scaler loaded successfully.")
    except Exception as e:
        print(f"[WARN] Scaler found but failed to load: {e}")

# Clear any corrupted buffer data on module load
traffic_buffer.clear()
print("[INFO] Traffic buffer initialized.")

def predict_traffic_anomaly(current_volume_bytes):
    """
    Predicts if current traffic volume is anomalous using LSTM.
    Returns: (is_anomaly, expected_volume, anomaly_score)
    """
    if not lstm_model:
        return False, 0, current_volume_bytes
    
    # 1. Scale Input
    if traffic_scaler:
        try:
            # Reshape to 2D array for scaler and force conversion to Python float
            scaled_result = traffic_scaler.transform([[current_volume_bytes]])
            # Use .item() to extract Python scalar from numpy array
            scaled_vol = float(np.asarray(scaled_result[0][0]).item())
        except Exception as e:
            print(f"[WARN] Scaler transform failed: {e}")
            scaled_vol = 0.0
    else:
        scaled_vol = float(current_volume_bytes)

    # Add to rolling buffer (ensure it's a Python float, not numpy scalar)
    traffic_buffer.append(scaled_vol)

    # We need exactly 10 data points to make a prediction
    if len(traffic_buffer) < 10:
        return False, 0, current_volume_bytes

    # Prepare input for LSTM (Batch Size, Time Steps, Features)
    # CRITICAL: Clean the buffer of any numpy objects and convert to pure Python floats
    try:
        # Extract all values and force convert to Python float
        clean_values = []
        for val in traffic_buffer:
            if isinstance(val, np.ndarray):
                # If it's an array, extract the scalar
                clean_values.append(float(np.asarray(val).item()))
            else:
                clean_values.append(float(val))
        
        # Now create numpy array from clean Python floats
        input_seq = np.array(clean_values, dtype=np.float32).reshape(1, 10, 1)
    except Exception as e:
        print(f"[ERROR] Failed to prepare LSTM input: {e}")
        print(f"[DEBUG] Buffer contents: {list(traffic_buffer)}")
        # Clear corrupted buffer
        traffic_buffer.clear()
        return False, 0, current_volume_bytes
    
    # 2. Predict Next Value
    try:
        predicted_scaled = lstm_model.predict(input_seq, verbose=0)[0][0]
        # Convert to Python float immediately
        predicted_scaled = float(np.asarray(predicted_scaled).item())
    except Exception as e:
        print(f"[ERROR] LSTM prediction failed: {e}")
        print(f"[DEBUG] Input shape: {input_seq.shape}, dtype: {input_seq.dtype}")
        return False, 0, current_volume_bytes
    
    # 3. Inverse Transform to get Real Bytes
    if traffic_scaler:
        try:
            result = traffic_scaler.inverse_transform([[predicted_scaled]])
            predicted_volume = float(np.asarray(result[0][0]).item())
        except Exception as e:
            print(f"[ERROR] Inverse transform failed: {e}")
            predicted_volume = float(predicted_scaled)
    else:
        predicted_volume = float(predicted_scaled)

    # 4. Anomaly Logic
    error = abs(current_volume_bytes - predicted_volume)
    
    if predicted_volume < 1: predicted_volume = 1 # Avoid div/0
    
    anomaly_score = error / predicted_volume
    
    # Threshold: If actual traffic is > 50% different from prediction, flag it.
    threshold = 0.5 
    is_anomaly = anomaly_score > threshold
    
    return is_anomaly, float(predicted_volume), float(anomaly_score)