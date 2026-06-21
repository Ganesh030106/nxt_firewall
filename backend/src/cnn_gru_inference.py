"""
cnn_gru_inference.py

Utility to load and run inference with the trained CNN-GRU model.
"""

import numpy as np
import os
import threading
import multiprocessing

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'models', 'cnn_gru_model.h5')

class CNNGRUDetector:
    def __init__(self):
        self.model = None
        self.loading = False
        # Only start background thread if in the MainProcess
        if multiprocessing.current_process().name == 'MainProcess':
            self.loading = True
            threading.Thread(target=self._load_model_bg, daemon=True).start()

    def _load_model_bg(self):
        print("[INFO] Loading CNN-GRU Model in background thread...")
        try:
            try:
                from tensorflow.keras.models import load_model
            except Exception:
                from keras.models import load_model
                
            if os.path.exists(MODEL_PATH):
                self.model = load_model(MODEL_PATH)
                print("[INFO] CNN-GRU Model loaded successfully.")
            else:
                print(f"[WARN] CNN-GRU model not found at {MODEL_PATH}")
        except Exception as e:
            print(f"[ERROR] Failed to load CNN-GRU model in background: {e}")
        finally:
            self.loading = False

    def predict(self, sequence):
        """
        sequence: np.array of shape (sequence_length, num_features)
        Returns: (is_malicious, confidence)
        """
        if self.model is None:
            return False, 0.0
        x = np.expand_dims(sequence, axis=0)
        preds = self.model.predict(x)
        is_malicious = np.argmax(preds) == 1
        confidence = float(np.max(preds))
        return is_malicious, confidence
