"""Geographical IP Blocking Module

Provides country-based IP filtering using ip-api.com service.
Features intelligent caching to minimize API calls and rate limiting.

Configuration:
    BLOCKED_COUNTRIES: List of 2-letter country codes to block
    API_TIMEOUT: Request timeout in seconds
    CACHE_MAX_SIZE: Maximum number of cached IP resolutions
"""

import requests
import logging
from collections import OrderedDict

# Configure logging
logger = logging.getLogger(__name__)

# --- CONFIGURATION ---
# Country codes to block (ISO 3166-1 alpha-2 format)
BLOCKED_COUNTRIES = ["CN", "RU", "KP", "BR"]

# API Configuration
API_TIMEOUT = 2  # seconds
API_ENDPOINT = "http://ip-api.com/json/{ip}?fields=countryCode"
CACHE_MAX_SIZE = 10000  # Maximum cached entries

# --- ENHANCED CACHE (LRU with size limit) ---
class GeoCache:
    """LRU cache with maximum size limit for IP geolocation data."""
    
    def __init__(self, max_size=CACHE_MAX_SIZE):
        self.cache = OrderedDict()
        self.max_size = max_size
        self.hits = 0
        self.misses = 0
    
    def get(self, ip):
        """Retrieve cached country code for IP."""
        if ip in self.cache:
            self.hits += 1
            # Move to end (most recently used)
            self.cache.move_to_end(ip)
            return self.cache[ip]
        self.misses += 1
        return None
    
    def set(self, ip, country_code):
        """Cache country code for IP."""
        # Remove oldest if at capacity
        if len(self.cache) >= self.max_size:
            self.cache.popitem(last=False)
        self.cache[ip] = country_code
    
    def get_stats(self):
        """Return cache statistics."""
        total = self.hits + self.misses
        hit_rate = (self.hits / total * 100) if total > 0 else 0
        return {
            'size': len(self.cache),
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': f"{hit_rate:.2f}%"
        }

geo_cache = GeoCache()

# --- LOCAL IP DETECTION ---
LOCAL_IP_PREFIXES = ("192.168.", "10.", "127.", "172.16.", "172.31.", "169.254.")

def is_local_ip(ip):
    """Check if IP is a local/private address."""
    return ip.startswith(LOCAL_IP_PREFIXES)


def get_country_code(ip):
    """
    Resolves IP address to ISO 3166-1 alpha-2 country code.
    
    Uses three-tier lookup strategy:
    1. Check in-memory cache (fastest)
    2. Identify local/private IPs (fast)
    3. Query external API (slow, rate-limited)
    
    Args:
        ip (str): IP address to resolve
        
    Returns:
        str: Two-letter country code or special codes:
             'LO' for local/private IPs
             'XX' for unknown/failed lookups
    """
    # Validate input
    if not ip or not isinstance(ip, str):
        return "XX"
    
    # 1. Check cache first (O(1) lookup)
    cached = geo_cache.get(ip)
    if cached:
        return cached
    
    # 2. Detect local/private IPs (no API call needed)
    if is_local_ip(ip):
        geo_cache.set(ip, "LO")
        return "LO"

    # 3. Query external API (with timeout protection)
    try:
        response = requests.get(
            API_ENDPOINT.format(ip=ip),
            timeout=API_TIMEOUT,
            headers={'User-Agent': 'SentinelX-Firewall/1.0'}
        )
        
        if response.status_code == 200:
            data = response.json()
            country = data.get("countryCode", "XX")
            
            # Cache successful result
            geo_cache.set(ip, country)
            return country
        else:
            logger.warning(f"GeoIP API returned status {response.status_code} for {ip}")
            
    except requests.Timeout:
        logger.debug(f"GeoIP API timeout for {ip}")
    except requests.RequestException as e:
        logger.debug(f"GeoIP API error for {ip}: {e}")
    except Exception as e:
        logger.error(f"Unexpected error in get_country_code: {e}")
    
    # Cache failed lookups to prevent repeated API calls
    geo_cache.set(ip, "XX")
    return "XX"


def check_geo_block(ip):
    """
    Determines if IP should be blocked based on geographical location.
    
    Args:
        ip (str): IP address to check
        
    Returns:
        tuple: (should_block: bool, country_code: str)
               should_block is True if IP is from a blocked country
    """
    country = get_country_code(ip)
    should_block = country in BLOCKED_COUNTRIES
    
    if should_block:
        logger.info(f"Geo-blocking IP {ip} from country {country}")
    
    return should_block, country


def get_cache_stats():
    """Retrieve cache performance statistics."""
    return geo_cache.get_stats()