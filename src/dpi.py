"""Deep Packet Inspection (DPI) Module

Provides real-time payload analysis for detecting web application attacks.
Uses pre-compiled regex patterns for high-performance pattern matching.

Detection Capabilities:
- SQL Injection (SQLi) attacks
- Cross-Site Scripting (XSS) attacks
- Command injection attempts
"""

import re
import logging

# Configure logging
logger = logging.getLogger(__name__)

# Pre-compiled Regex Patterns for Performance
SQLI_PATTERNS = [
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",            # Classic ' or -- or #
    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", # = followed by ' or ;
    r"\w*((\%27)|(\'))(\s*)((\%6F)|o|(\%4F))((\%72)|r|(\%52))", # ' OR
    r"exec(\s|\+)+(s|x)p\w+",                    # exec sp_...
    r"(union|select|insert|update|delete|drop|create)\s+(all|distinct|from|where)", # SQL keywords
]

XSS_PATTERNS = [
    r"((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)", # <script>, <iframe>
    r"((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)", # <img> tag
    r"javascript:",                                  # javascript: protocol
    r"on(error|load|click|mouse)\s*=",              # Event handlers
]

# Compile them once when the module loads
compiled_sqli = [re.compile(p, re.IGNORECASE) for p in SQLI_PATTERNS]
compiled_xss = [re.compile(p, re.IGNORECASE) for p in XSS_PATTERNS]

# Statistics tracking
_stats = {
    'packets_inspected': 0,
    'sqli_detected': 0,
    'xss_detected': 0,
    'decoding_errors': 0
}

# Payload Inspection Function
def inspect_payload(payload_bytes):
    """
    Scans raw packet payload for SQLi and XSS signatures.
    
    Args:
        payload_bytes (bytes): Raw packet payload data
        
    Returns:
        tuple: (is_threat: bool, threat_type: str or None, confidence: float)
    """
    if not payload_bytes:
        return False, None, 0.0
    
    _stats['packets_inspected'] += 1
    
    try:
        # Decode payload to string (ignore errors for binary data)
        payload_str = payload_bytes.decode('utf-8', errors='ignore')
        
        # Skip very short payloads
        if len(payload_str) < 3:
            return False, None, 0.0
        
        # 1. Check SQL Injection
        for pattern in compiled_sqli:
            if pattern.search(payload_str):
                _stats['sqli_detected'] += 1
                logger.debug(f"SQL Injection detected in payload")
                return True, "SQL Injection Attempt", 1.0
        
        # 2. Check XSS
        for pattern in compiled_xss:
            if pattern.search(payload_str):
                _stats['xss_detected'] += 1
                logger.debug(f"XSS detected in payload")
                return True, "XSS Payload Detected", 1.0
                
    except UnicodeDecodeError:
        _stats['decoding_errors'] += 1
        logger.debug("Payload decoding failed (likely binary data)")
    except Exception as e:
        logger.error(f"DPI inspection error: {e}")

    return False, None, 0.0


def get_dpi_stats():
    """Returns DPI engine statistics."""
    return _stats.copy()