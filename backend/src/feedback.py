import os
import pandas as pd
import joblib
from sklearn.svm import OneClassSVM

# --- PATH CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
DATA_PATH = os.path.join(PROJECT_ROOT, "models", "feedback_data.csv")
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "feedback_brain.pkl")

# Define columns matching the Main Model's input
COLUMNS = ["src_bytes", "protocol_type", "service", "flag"]

# --- FEEDBACK MODEL FUNCTIONS ---
def load_feedback_model():
    """Loads the separate feedback model if it exists."""
    if os.path.exists(MODEL_PATH):
        try:
            return joblib.load(MODEL_PATH)
        except:
            return None
    return None


# --- FEEDBACK MODEL FUNCTIONS ---
def add_feedback_entry(features):
    """
    Appends a False Positive entry to the separate dataset.
    features: list or dict containing [src_bytes, protocol, service, flag] (Encoded)
    """
    # 1. Create DataFrame
    df_new = pd.DataFrame([features], columns=COLUMNS)
    
    # 2. Append to CSV (Create if doesn't exist)
    if not os.path.exists(DATA_PATH):
        df_new.to_csv(DATA_PATH, index=False)
    else:
        df_new.to_csv(DATA_PATH, mode='a', header=False, index=False)
    
    print(f"[FEEDBACK] Added new False Positive entry to {DATA_PATH}")
    
    # 3. Trigger Retraining Immediately
    retrain_feedback_model()

# RETRAINING FUNCTION
def retrain_feedback_model():
    """
    Separate Training Pipeline.
    Trains a One-Class SVM on the feedback data only.
    """
    if not os.path.exists(DATA_PATH):
        return

    try:
        # 1. Load Data
        df = pd.read_csv(DATA_PATH)
        
        # We need at least a few samples to train a meaningful model
        if len(df) < 2:
            print("[FEEDBACK] Not enough data to train feedback model yet.")
            return

        X = df[COLUMNS]

        # 2. Train One-Class SVM
        # nu=0.1 means we allow some variance, gamma='auto' for feature scaling
        clf = OneClassSVM(nu=0.1, kernel="rbf", gamma='auto')
        clf.fit(X)

        # 3. Save Separate .pkl File
        joblib.dump(clf, MODEL_PATH)
        print(f"[FEEDBACK] ✅ Feedback Model Retrained & Saved to {MODEL_PATH}")

    except Exception as e:
        print(f"[FEEDBACK] ❌ Retraining Failed: {e}")

# OVERRIDE CHECK FUNCTION
def check_feedback_override(features, model):
    """
    Checks if the feedback model recognizes this packet as Safe.
    Returns: True (Override Block) or False (Keep Block)
    """
    if not model:
        return False
        
    try:
        # Transform input to DataFrame
        df = pd.DataFrame([features], columns=COLUMNS)
        
        # Predict: 1 = Inlier (Looks like safe feedback data), -1 = Outlier
        prediction = model.predict(df)[0]
        
        if prediction == 1:
            return True # This matches a known False Positive pattern
            
    except Exception as e:
        print(f"[FEEDBACK] Prediction Error: {e}")
        
    return False