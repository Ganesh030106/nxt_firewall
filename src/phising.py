"""Phishing Detection Module

Provides ML-based URL analysis to detect phishing websites.
Uses trained scikit-learn model with feature extraction from URL characteristics.

Features Analyzed:
- IP address usage in URL
- URL length and structure
- Use of URL shorteners
- Special characters and redirects
- HTTPS usage
- Domain characteristics
"""

# src/phishing.py
import joblib
import re
import os
import numpy as np
import logging
from urllib.parse import urlparse

# Configure logging
logger = logging.getLogger(__name__)

# Fix: Dynamically locate the model file relative to this script
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")

model = None

# Load model on startup
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        logger.info("Phishing ML model loaded successfully")
        print("[INFO] Phishing ML Model Loaded.")
    except Exception as e:
        logger.error(f"Failed to load phishing model: {e}")
        print(f"[WARN] Failed to load phishing model: {e}")
else:
    logger.warning(f"Phishing model not found at: {MODEL_PATH}")
    print(f"[WARN] Phishing Model not found at: {MODEL_PATH}")


def extract_features_from_url(url):
    """
    Extracts 30 features from URL for ML model prediction.
    
    Note: This is a simplified implementation for demo stability.
    Production systems should extract all 30 features from training data.
    
    Args:
        url (str): URL to analyze
        
    Returns:
        np.array: Feature vector of shape (1, 30)
    """
    if not url or not isinstance(url, str):
        return np.array([[1] * 30])  # Default safe features
    
    features = []
    
    try:
        # 1. IP Address Check (-1 = has IP, 1 = no IP)
        ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])" 
        features.append(-1 if re.search(ip_pattern, url) else 1)

        # 2. URL Length (1=short/safe, 0=medium, -1=long/suspicious)
        if len(url) < 54:
            features.append(1)
        elif len(url) <= 75:
            features.append(0)
        else:
            features.append(-1)

        # 3. URL Shorteners (-1 = shortener, 1 = normal)
        shorteners = r"bit\.ly|goo\.gl|shorte\.st|x\.co|tinyurl|is\.gd"
        features.append(-1 if re.search(shorteners, url) else 1)

        # 4. @ Symbol in URL (-1 = has @, 1 = no @)
        features.append(-1 if "@" in url else 1)

        # 5. Double Slash Redirect (-1 = suspicious, 1 = normal)
        features.append(-1 if url.rfind('//') > 7 else 1)

        # 6. Dash in Domain (-1 = has dash, 1 = no dash)
        features.append(-1 if '-' in urlparse(url).netloc else 1)

        # 7. Number of Subdomains (1 = normal, 0 = medium, -1 = many)
        dots = urlparse(url).netloc.count('.')
        features.append(1 if dots == 1 else (0 if dots == 2 else -1))

        # 8. HTTPS (1 = HTTPS, -1 = HTTP)
        features.append(1 if "https" in url.lower() else -1)

        # Fill remaining features with defaults to match model shape (30 total)
        for _ in range(22):
            features.append(1)
    
    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        # Return safe default features
        features = [1] * 30

    return np.array([features])


def check_url_safety(url):
    """Returns (is_phishing, confidence, reason)"""
    if not model:
        return False, 0.0, "Model Not Loaded"

    try:
        features = extract_features_from_url(url)
        prediction = model.predict(features)[0] # 1 = Safe, -1 = Phishing
        confidence = max(model.predict_proba(features)[0])
        
        if prediction == -1:
            return True, confidence, "AI Detected Malicious Pattern"
        else:
            return False, confidence, "Verified Safe by AI"
            
    except Exception as e:
        return False, 0.0, f"Error: {str(e)}"