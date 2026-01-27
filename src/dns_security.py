"""DNS Security Module

Provides DNS-layer threat detection and mitigation:
- DNS tunneling detection (covert channel prevention)
- Malicious domain blacklist checking
- Sinkhole response injection for blocked domains

Techniques:
- Shannon entropy analysis for DGA detection
- Domain length heuristics
- Automated sinkhole response generation
"""

#imports
import math
import collections
import logging
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
# Known malicious domains (should be expanded or integrated with threat intelligence)
MALICIOUS_DOMAINS_DB = ["badsite.com", "malware-c2.org", "tunnel.test"]

# Sinkhole configuration
SINKHOLE_IP = "10.10.10.10"         # Fake IP returned to attackers
ENTROPY_THRESHOLD = 3.5              # Randomness threshold (3.5-4.5 typical for DGA)
MAX_DOMAIN_LENGTH = 50               # Legitimate domains are usually shorter

# Statistics tracking
_stats = {
    'queries_checked': 0,
    'tunneling_detected': 0,
    'blacklist_hits': 0,
    'sinkhole_responses': 0
}

# DETECTION LOGIC
def calculate_entropy(string):
    """
    Calculates Shannon Entropy to detect random-looking subdomains.
    
    Domain Generation Algorithms (DGA) produce high-entropy domains like
    'a83b27z9.tunnel.com' versus normal domains like 'google.com'.
    
    Args:
        string (str): Domain name or subdomain to analyze
        
    Returns:
        float: Shannon entropy value (0-8, higher = more random)
    """
    if not string:
        return 0
    
    try:
        # Calculate character frequency
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        # Calculate Shannon entropy
        entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy
    except Exception as e:
        logger.error(f"Entropy calculation error: {e}")
        return 0

# TUNNELING DETECTION
def is_dns_tunneling(query_name):
    """
    Analyzes domain name characteristics for tunneling indicators.
    Returns: (is_tunneling, reason)
    """
    # 1. Check Query Length (Tunneling payloads are long)
    if len(query_name) > MAX_DOMAIN_LENGTH:
        return True, "Abnormal Query Length"

    # 2. Check Entropy (Random chars indicate encrypted data)
    entropy = calculate_entropy(query_name)
    if entropy > ENTROPY_THRESHOLD:
        return True, f"High Entropy ({entropy:.2f})"

    # 3. Check specific TXT/NULL record indicators (Simplified for demo)
    # (In a full system, you'd check query type, but packet structure varies)
    
    return False, "Clean"

# BLACKLIST CHECK
def check_malicious_domain(query_name):
    """
    Checks if domain is in the static blacklist.
    """
    # Remove trailing dot (e.g., 'google.com.' -> 'google.com')
    clean_name = query_name.rstrip(".")
    
    # Check exact match or subdomain
    for bad_domain in MALICIOUS_DOMAINS_DB:
        if clean_name == bad_domain or clean_name.endswith("." + bad_domain):
            return True
    return False

# SINKHOLE RESPONSE FORGER
def forge_sinkhole_response(original_pkt):
    """
    Creates a fake DNS response pointing to the Sinkhole IP.
    """
    # 1. Extract details from the original request
    ip_layer = original_pkt[IP]
    udp_layer = original_pkt[UDP]
    dns_layer = original_pkt[DNS]
    qname = dns_layer.qd.qname

    # 2. Craft the Spoofed Response
    # Swap Src/Dst IP and Ports
    spoofed_pkt = (
        IP(src=ip_layer.dst, dst=ip_layer.src) /
        UDP(sport=udp_layer.dport, dport=udp_layer.sport) /
        DNS(
            id=dns_layer.id,      # Match Transaction ID
            qr=1,                 # 1 = Response
            aa=1,                 # Authoritative Answer
            rd=dns_layer.rd,      # Recursion Desired (Copy)
            qd=dns_layer.qd,      # Copy Question
            an=DNSRR(             # Answer Record
                rrname=qname,
                ttl=10,
                rdata=SINKHOLE_IP # <--- THE TRAP IP
            )
        )
    )
    return spoofed_pkt