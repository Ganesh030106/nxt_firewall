import datetime
from src.geo import check_geo_block # Reuse your existing Geo logic

# --- POLICY DEFINITIONS ---
TRUST_THRESHOLD = 50  # Access allowed if score > 50
OFFICE_HOURS = (8, 19) # 8 AM to 7 PM

def get_context_score(src_ip, protocol, packet_len):
    """
    Calculates a Zero Trust Score (0-100).
    0 = Untrusted (Block), 100 = Trusted.
    """
    score = 100
    reasons = []

    # 1. TIME CONTEXT (Reduce score for weird hours)
    current_hour = datetime.datetime.now().hour
    if not (OFFICE_HOURS[0] <= current_hour <= OFFICE_HOURS[1]):
        score -= 20
        reasons.append("Outside Office Hours")

    # 2. GEO CONTEXT (Reduce score for non-local traffic)
    # Assuming local IPs are trusted
    if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip == "127.0.0.1":
        pass # Trusted local
    else:
        # Check if country is blocked
        is_blocked, country = check_geo_block(src_ip)
        if is_blocked:
            score -= 100 # Immediate Fail
            reasons.append(f"Banned Country ({country})")
        elif country != "IN": # Example: Reduce trust for foreign IPs
            score -= 30
            reasons.append("Foreign IP")

    # 3. BEHAVIOR CONTEXT (Payload anomalies)
    if packet_len > 1500: # Jumbo packet
        score -= 40
        reasons.append("Abnormal Payload Size")

    # 4. PROTOCOL CONTEXT
    if protocol not in ["http", "https", "ssh", "dns_u"]:
        score -= 10
        reasons.append("Uncommon Protocol")

    return max(score, 0), reasons

def enforce_zero_trust(src_ip, protocol, packet_len):
    """
    Main entry point for ZTA enforcement.
    Returns: (Allowed (bool), Message)
    """
    score, reasons = get_context_score(src_ip, protocol, packet_len)
    
    if score < TRUST_THRESHOLD:
        return False, f"Zero Trust Deny (Score: {score}/100). Reasons: {', '.join(reasons)}"
    
    return True, "Access Granted"