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
import tldextract
import whois
import requests
import idna
import socket
import ssl

# Configure logging
logger = logging.getLogger(__name__)

import threading
import multiprocessing

# Fix: Dynamically locate the model file relative to this script
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
MODEL_PATH = os.path.join(PROJECT_ROOT, "models", "phishing_model.pkl")

model = None
model_loading = False

def _bg_load_phishing_model():
    global model, model_loading
    if model_loading:
        return
    model_loading = True
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
    model_loading = False

# Only load model in the MainProcess to avoid child process loading overhead
if multiprocessing.current_process().name == 'MainProcess':
    threading.Thread(target=_bg_load_phishing_model, daemon=True).start()



def extract_features_from_url(url):
    """
    Advanced feature extraction for phishing detection.
    Returns: (features, reasons) where reasons is a list of explainable findings.
    """
    if not url or not isinstance(url, str):
        return np.array([[1] * 30]), ["Invalid URL"]

    features = []
    reasons = []
    try:
        # 1. IP Address in URL
        ip_pattern = r"(([01]?\d\d?|2[0-4]\d|25[0-5])\.){3}([01]?\d\d?|2[0-4]\d|25[0-5])"
        if re.search(ip_pattern, url):
            features.append(-1)
            reasons.append("URL contains IP address")
        else:
            features.append(1)

        # 2. URL Length
        if len(url) < 54:
            features.append(1)
        elif len(url) <= 75:
            features.append(0)
            reasons.append("Medium URL length")
        else:
            features.append(-1)
            reasons.append("Long URL length")

        # 3. URL Shortener
        shorteners = r"bit\.ly|goo\.gl|shorte\.st|x\.co|tinyurl|is\.gd"
        if re.search(shorteners, url):
            features.append(-1)
            reasons.append("URL uses shortener")
        else:
            features.append(1)

        # 4. @ Symbol
        if "@" in url:
            features.append(-1)
            reasons.append("@ symbol in URL")
        else:
            features.append(1)

        # 5. Double Slash Redirect
        features.append(-1 if url.rfind('//') > 7 else 1)

        # 6. Dash in Domain
        domain = urlparse(url).netloc
        if '-' in domain:
            features.append(-1)
            reasons.append("Dash in domain name")
        else:
            features.append(1)

        # 7. Number of Subdomains
        dots = domain.count('.')
        features.append(1 if dots == 1 else (0 if dots == 2 else -1))
        if dots > 2:
            reasons.append("Many subdomains")

        # 8. HTTPS
        if url.lower().startswith("https"):
            features.append(1)
        else:
            features.append(-1)
            reasons.append("No HTTPS")

        # 9. Suspicious Unicode (Homograph)
        try:
            ascii_domain = idna.decode(domain)
        except Exception:
            ascii_domain = domain
        if any(ord(c) > 127 for c in ascii_domain):
            features.append(-1)
            reasons.append("Suspicious Unicode in domain (possible homograph)")
        else:
            features.append(1)

        # 10. Brand Name Similarity (simple check for 'login', 'secure', etc.)
        brand_keywords = ["login", "secure", "update", "verify", "account", "bank", "paypal"]
        if any(word in url.lower() for word in brand_keywords):
            features.append(-1)
            reasons.append("Brand keyword in URL")
        else:
            features.append(1)

        # 11. Domain Age (WHOIS)
        try:
            ext = tldextract.extract(url)
            domain_name = f"{ext.domain}.{ext.suffix}"
            w = whois.whois(domain_name)
            if hasattr(w, 'creation_date') and w.creation_date:
                from datetime import datetime
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date
                age_days = (datetime.now() - creation_date).days
                if age_days < 180:
                    features.append(-1)
                    reasons.append("Domain age < 6 months")
                else:
                    features.append(1)
            else:
                features.append(0)
                reasons.append("Domain age unknown")
        except Exception:
            features.append(0)
            reasons.append("WHOIS lookup failed")

        # 12. SSL Certificate Validity
        try:
            if url.lower().startswith("https"):
                hostname = ext.registered_domain
                ctx = ssl.create_default_context()
                with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                    s.settimeout(3)
                    s.connect((hostname, 443))
                    cert = s.getpeercert()
                features.append(1)
            else:
                features.append(-1)
                reasons.append("No SSL certificate")
        except Exception:
            features.append(0)
            reasons.append("SSL check failed")

        # Fill remaining features with defaults to match model shape (30 total)
        while len(features) < 30:
            features.append(1)
    except Exception as e:
        logger.error(f"Feature extraction error: {e}")
        features = [1] * 30
        reasons.append(f"Feature extraction error: {e}")
    return np.array([features]), reasons


def check_url_safety(url):
    """
    Returns (is_phishing, confidence, reasons) with explainable results and threat feed integration.
    """
    if not model:
        return False, 0.0, ["Model Not Loaded"]

    reasons = []
    # Real-time threat intelligence feeds
    try:
        # Google Safe Browsing (pseudo, as API key is needed)
        # PhishTank (public API)
        phishtank_url = "https://checkurl.phishtank.com/checkurl/"
        resp = requests.post(phishtank_url, data={"url": url, "format": "json"}, timeout=3)
        if resp.status_code == 200 and 'phish_id' in resp.text:
            reasons.append("Blacklisted by PhishTank")
            return True, 1.0, reasons
    except Exception:
        pass

    try:
        features, feature_reasons = extract_features_from_url(url)
        reasons.extend(feature_reasons)
        prediction = model.predict(features)[0] # 1 = Safe, -1 = Phishing
        confidence = max(model.predict_proba(features)[0])
        if prediction == -1:
            reasons.append("AI Detected Malicious Pattern")
            return True, confidence, reasons
        else:
            return False, confidence, reasons or ["Verified Safe by AI"]
    except Exception as e:
        return False, 0.0, [f"Error: {str(e)}"]