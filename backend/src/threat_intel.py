"""Global Threat Intelligence Module

Automatically downloads and maintains threat feeds from public sources.
Provides fast O(1) IP reputation lookups with thread-safe updates.

Features:
- Automatic feed updates every hour
- Multiple threat feed sources
- Thread-safe cache updates
- Statistics tracking
- Graceful error handling
"""

import requests
import threading
import time
import re
import logging
from datetime import datetime

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
# Public threat intelligence feeds (no API key required)
THREAT_FEEDS = [
    {
        'name': 'Emerging Threats',
        'url': 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt',
        'timeout': 10
    },
    {
        'name': 'Feodo Tracker',
        'url': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
        'timeout': 10
    }
]

UPDATE_INTERVAL = 3600  # seconds (1 hour)
IP_REGEX = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- GLOBAL STATE ---
# Thread-safe set for O(1) lookup performance
_threat_cache = set()
_cache_lock = threading.Lock()
_last_update = None
_update_stats = {
    'total_updates': 0,
    'successful_updates': 0,
    'failed_updates': 0,
    'total_ips': 0
}


def fetch_threat_ips():
    """
    Downloads threat intelligence from configured feeds.
    
    Atomically updates global cache with thread-safe lock.
    Maintains statistics for monitoring and debugging.
    """
    global _threat_cache, _last_update, _update_stats
    
    new_ips = set()
    _update_stats['total_updates'] += 1
    
    logger.info("Starting threat intelligence feed update...")
    print("[INTEL] Downloading Global Threat Feeds...")

    for feed in THREAT_FEEDS:
        feed_name = feed['name']
        feed_url = feed['url']
        
        try:
            response = requests.get(
                feed_url,
                timeout=feed.get('timeout', 10),
                headers={'User-Agent': 'SentinelX-Firewall/1.0'}
            )
            
            if response.status_code == 200:
                # Extract valid IPv4 addresses using regex
                found_ips = IP_REGEX.findall(response.text)
                
                # Validate and filter IPs
                valid_ips = {ip for ip in found_ips if validate_ip(ip)}
                new_ips.update(valid_ips)
                
                logger.info(f"Loaded {len(valid_ips)} IPs from {feed_name}")
                print(f"[INTEL] Loaded {len(valid_ips)} IPs from {feed_url}")
            else:
                logger.warning(f"Feed {feed_name} returned status {response.status_code}")
                print(f"[INTEL] Failed to fetch {feed_name}: HTTP {response.status_code}")
                
        except requests.Timeout:
            logger.error(f"Timeout fetching {feed_name}")
            print(f"[INTEL] Timeout: {feed_name}")
        except requests.RequestException as e:
            logger.error(f"Error fetching {feed_name}: {e}")
            print(f"[INTEL] Failed to fetch {feed_name}: {e}")
        except Exception as e:
            logger.error(f"Unexpected error processing {feed_name}: {e}")

    # Atomic update with thread safety
    if new_ips:
        with _cache_lock:
            _threat_cache = new_ips
            _last_update = datetime.now()
            _update_stats['successful_updates'] += 1
            _update_stats['total_ips'] = len(new_ips)
        
        logger.info(f"Threat cache updated: {len(new_ips)} total IPs")
        print(f"[INTEL] Threat Intelligence Updated. Total Blocked IPs: {len(new_ips)}")
    else:
        _update_stats['failed_updates'] += 1
        logger.warning("No threat IPs found in feeds, keeping existing cache")
        print("[INTEL] No new IPs found. Keeping old cache.")


def validate_ip(ip):
    """
    Basic IP address validation.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid IPv4 address
    """
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def is_global_threat(ip):
    """
    Checks if IP address is in global threat intelligence blocklist.
    
    Thread-safe O(1) lookup using set membership test.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        bool: True if IP is on threat blocklist
    """
    if not ip:
        return False
    
    with _cache_lock:
        return ip in _threat_cache


def get_threat_stats():
    """
    Returns current threat intelligence statistics.
    
    Returns:
        dict: Statistics including cache size, update counts, last update time
    """
    with _cache_lock:
        return {
            'cache_size': len(_threat_cache),
            'last_update': _last_update.isoformat() if _last_update else None,
            'total_updates': _update_stats['total_updates'],
            'successful_updates': _update_stats['successful_updates'],
            'failed_updates': _update_stats['failed_updates']
        }


def start_threat_intel_updater():
    """
    Starts background thread for automatic threat feed updates.
    
    Performs initial update immediately, then updates every hour.
    Runs as daemon thread to allow clean shutdown.
    """
    def update_loop():
        # Initial update on startup
        try:
            fetch_threat_ips()
        except Exception as e:
            logger.error(f"Initial threat feed update failed: {e}")
        
        # Continuous update loop
        while True:
            try:
                time.sleep(UPDATE_INTERVAL)
                fetch_threat_ips()
            except Exception as e:
                logger.error(f"Threat feed update error: {e}")
    
    thread = threading.Thread(target=update_loop, daemon=True, name="ThreatIntelUpdater")
    thread.start()
    logger.info(f"Threat intelligence updater started (interval: {UPDATE_INTERVAL}s)")