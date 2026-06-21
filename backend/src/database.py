import sqlite3
import datetime
import time
import os
import csv
import shutil
import json
import logging
import re
from ipaddress import IPv4Address, AddressValueError


# --- LOGGING CONFIGURATION ---
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- PATH SETUP ---
# DB_PATH = "logs/firewall_logs.db"
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DB_PATH = os.path.join(LOG_DIR, "firewall_logs.db")

# Ensure logs folder exists
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)


# --- INPUT VALIDATION UTILITIES (CRITICAL FIX 1.1 & 1.3) ---

def validate_ip_address(ip_str):
    """Validates and normalizes IP address (CRITICAL FIX 1.3)."""
    try:
        # Remove whitespace
        ip_str = str(ip_str).strip()
        
        # Validate using ipaddress module
        ipv4 = IPv4Address(ip_str)
        return str(ipv4)
    except (AddressValueError, ValueError, TypeError):
        return None


def validate_action_filter(action_filter):
    """Validates action filter against whitelist (CRITICAL FIX 1.1)."""
    valid_actions = {"BLOCKED", "ALLOWED", "ALERT", "QUARANTINED", "SINKHOLED", "ALL"}
    if action_filter and action_filter in valid_actions:
        return action_filter
    return "ALL"


def sanitize_search_query(search_query, max_length=256):
    """Sanitizes search query to prevent SQL injection (CRITICAL FIX 1.1)."""
    if not isinstance(search_query, str):
        return ""
    
    # Limit length
    search_query = search_query[:max_length]
    
    # Remove dangerous characters but allow basic search
    # Allow alphanumeric, dots, dashes, colons, slashes
    search_query = re.sub(r'[^\w\s\.\-\:\/%]', '', search_query)
    
    return search_query.strip()


def validate_limit(limit, max_limit=1000, default=50):
    """Validates and constrains query limit (CRITICAL FIX 1.1)."""
    try:
        limit = int(limit)
        if limit < 1:
            return default
        return min(limit, max_limit)
    except (ValueError, TypeError):
        return default
    
# --- DATABASE INITIALIZATION ---
def init_db():
    """Initialize database with proper indexes."""
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)

    # Enable WAL mode and pragmas
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA cache_size = -64000;")  
    # 64MB cache
    conn.execute("PRAGMA temp_store = MEMORY;")  
    # Temp tables in RAM

    c = conn.cursor()
    
    # Main Logs Table
    c.execute('''CREATE TABLE IF NOT EXISTS logs 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  timestamp TEXT, 
                  src_ip TEXT, 
                  dst_ip TEXT, 
                  protocol TEXT, 
                  action TEXT, 
                  confidence REAL, 
                  reason TEXT, 
                  pcap_file TEXT)''')
                  
    # CREATE INDEXES for common queries
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp DESC)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_src_ip ON logs(src_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_dst_ip ON logs(dst_ip)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_action ON logs(action)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_reason ON logs(reason)')
    
    # Composite index for common filter combination
    c.execute('CREATE INDEX IF NOT EXISTS idx_logs_action_time ON logs(action, timestamp DESC)')


    # Custom Rules Table
    c.execute('''CREATE TABLE IF NOT EXISTS rules 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT, 
                  type TEXT, 
                  value TEXT, 
                  comment TEXT)''')
    
    # Heartbeat & Status
    c.execute('''CREATE TABLE IF NOT EXISTS system_status (id INTEGER PRIMARY KEY, last_seen REAL)''')
    
    # Whitelist
    c.execute('''CREATE TABLE IF NOT EXISTS whitelist (ip TEXT PRIMARY KEY, note TEXT)''')
    c.execute("INSERT OR IGNORE INTO whitelist (ip, note) VALUES (?, ?)", ("192.168.1.1", "Router"))
    c.execute("INSERT OR IGNORE INTO whitelist (ip, note) VALUES (?, ?)", ("8.8.8.8", "Google DNS"))

    # Settings
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)''')
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("blocking_mode", "ON"))
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ("sensitivity", "0.80"))

    # System Events
    c.execute('''CREATE TABLE IF NOT EXISTS system_events 
                 (id INTEGER PRIMARY KEY, timestamp TEXT, level TEXT, message TEXT)''')
    
    # Custom Blocking Rules Table
    c.execute('''CREATE TABLE IF NOT EXISTS custom_rules 
                 (id INTEGER PRIMARY KEY, type TEXT, value TEXT, timestamp TEXT)''')
    
    conn.commit()
    conn.close()

# Use prepared statements for frequent queries
class PreparedQueries:
    """Cache compiled SQL statements."""
    
    def __init__(self):
        self.queries = {}
        self.conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    
    def get_recent_logs_query(self):
        """Get cached prepared statement."""
        if 'recent_logs' not in self.queries:
            sql = """
                SELECT id, timestamp, src_ip, dst_ip, protocol, action, confidence, reason, pcap_file
                FROM logs
                WHERE action = ? OR action = ?
                ORDER BY id DESC
                LIMIT ?
            """
            self.queries['recent_logs'] = self.conn.prepare(sql)
        return self.queries['recent_logs']

# --- RULE ENGINE FUNCTIONS ---
# Custom Rules Management
def add_custom_rule(r_type, value):
    """Adds a rule (e.g., type='IP', value='1.2.3.4')"""
    try:
        conn = sqlite3.connect(DB_PATH)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO custom_rules (type, value, timestamp) VALUES (?, ?, ?)", 
                     (r_type, value, timestamp))
        conn.commit()
        conn.close()
        return True
    except:
        return False

# Retrieve Custom Rules
def get_custom_rules():
    """Returns all active rules"""
    try:
        conn = sqlite3.connect(DB_PATH)
        rules = conn.execute("SELECT id, type, value, timestamp FROM custom_rules").fetchall()
        conn.close()
        return [{"id": r[0], "type": r[1], "value": r[2], "time": r[3]} for r in rules]
    except:
        return []

# Remove Custom Rule
def delete_custom_rule(rule_id):
    """Removes a rule by ID"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM custom_rules WHERE id=?", (rule_id,))
        conn.commit()
        conn.close()
        return True
    except:
        return False

# --- LOGGING FUNCTIONS ---

# Log an Event
def log_event(src, dst, proto, action, confidence, reason="Unknown", pcap_file=""):
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO logs (timestamp, src_ip, dst_ip, protocol, action, confidence, reason, pcap_file) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                  (timestamp, src, dst, proto, action, confidence, reason, pcap_file))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB-ERROR] {e}")

# Log a System Event
def log_system_event(level, message):
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.execute("INSERT INTO system_events (timestamp, level, message) VALUES (?, ?, ?)", (timestamp, level, message))
        conn.commit()
        conn.close()
    except: pass

# --- GETTERS ---

# Fetch Logs with Filters
def get_logs(limit=50, search_query=None, action_filter=None):
    """
    Fetches logs with optional filtering logic (CRITICAL FIX 1.1 - SQL Injection Protection).
    
    Args:
        limit: Maximum number of logs to return (1-1000, default 50)
        search_query: Search text for IP, reason, or protocol (validated for length)
        action_filter: Action type filter (BLOCKED|ALLOWED|ALERT|QUARANTINED|SINKHOLED|ALL)
    
    Returns:
        List of log dictionaries with validation applied
    """
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        
        # CRITICAL FIX 1.1: Input Validation - Limit Parameter
        if not isinstance(limit, int) or limit < 1:
            limit = 50
        limit = min(limit, 1000)  # Cap at 1000 to prevent DoS
        
        # CRITICAL FIX 1.1: Input Validation - Action Filter
        action_filter = validate_action_filter(action_filter)
        
        # CRITICAL FIX 1.1: Input Validation - Search Query
        if search_query:
            # Validate search query: max 100 chars, no null bytes
            search_query = str(search_query).strip()
            if len(search_query) > 100 or '\x00' in search_query:
                search_query = None
            else:
                # Allow only alphanumeric, dots, dashes, underscores, slashes, spaces
                if not re.match(r'^[\w\-\.\s/]*$', search_query):
                    search_query = None
        
        # Base Query
        sql = "SELECT * FROM logs"
        params = []
        conditions = []

        # 1. Action Filter (e.g., 'BLOCKED', 'ALLOWED')
        if action_filter and action_filter != "ALL":
            conditions.append("action = ?")
            params.append(action_filter)

        # 2. Search Text (IP or Reason) - NOW FULLY PARAMETERIZED
        if search_query:
            conditions.append("(src_ip LIKE ? OR reason LIKE ? OR protocol LIKE ?)")
            wildcard = f"%{search_query}%"
            params.append(wildcard)
            params.append(wildcard)
            params.append(wildcard)

        # Apply Filters
        if conditions:
            sql += " WHERE " + " AND ".join(conditions)

        # Sort and Limit
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cursor = conn.execute(sql, params)
        rows = cursor.fetchall()
        conn.close()
        
        # Format for API
        data = []
        for row in rows:
            data.append({
                "id": row[0],
                "time": row[1],
                "src": row[2],
                "dst": row[3],
                "proto": row[4],
                "action": row[5],
                "conf": row[6],
                "reason": row[7],
                "pcap": row[8]
            })
        return data
    except Exception as e:
        logger.error(f"[DB ERROR in get_logs] {e}")
        return []

# Fetch System Events
def get_system_logs():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        logs = conn.execute("SELECT timestamp, level, message FROM system_events ORDER BY id DESC LIMIT 50").fetchall()
        conn.close()
        return logs
    except: return []

# Fetch Statistics
def get_stats():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        blocked = conn.execute("SELECT COUNT(*) FROM logs WHERE action='BLOCKED' OR action='ALERT'").fetchone()[0]
        total = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]
        conn.close()
        return {"blocked": blocked, "total": total}
    except: return {"blocked": 0, "total": 0}

# Heartbeat Functions
def get_system_status():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        row = conn.execute("SELECT last_seen FROM system_status WHERE id=1").fetchone()
        conn.close()
        if row and (time.time() - row[0] < 10): return True
    except: pass
    return False

# Update Heartbeat Timestamp
def update_heartbeat():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        now = time.time()
        if conn.execute("SELECT id FROM system_status WHERE id=1").fetchone():
            conn.execute("UPDATE system_status SET last_seen=? WHERE id=1", (now,))
        else:
            conn.execute("INSERT INTO system_status (id, last_seen) VALUES (1, ?)", (now,))
        conn.commit()
        conn.close()
    except: pass

# --- CONFIG & WHITELIST ---

# Whitelist Management
def get_whitelist():
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        ips = [row[0] for row in conn.execute("SELECT ip FROM whitelist").fetchall()]
        conn.close()
        return ips
    except: return []

# Add IP to Whitelist
def add_whitelist(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO whitelist (ip, note) VALUES (?, 'User Added')", (ip,))
    conn.commit()
    conn.close()

# Remove IP from Whitelist
def remove_whitelist(ip):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
    conn.commit()
    conn.close()

# Settings Management
def get_setting(key, default=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        conn.close()
        return row[0] if row else default
    except: return default

# Update Setting
def update_setting(key, value):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
    conn.commit()
    conn.close()

# --- LOG ROTATION & ARCHIVING ---
# Archive Old Logs
def archive_old_logs(retention_days=5):
    """
    Moves logs older than 'retention_days' to a CSV file and deletes them from DB.
    """
    try:
        # 1. Setup Paths
        archive_dir = os.path.join(LOG_DIR, "archives")
        if not os.path.exists(archive_dir):
            os.makedirs(archive_dir)
            
        # 2. Calculate Cutoff Date
        cutoff_date = datetime.datetime.now() - datetime.timedelta(days=retention_days)
        cutoff_str = cutoff_date.strftime("%Y-%m-%d %H:%M:%S")
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # 3. Select Old Logs
        c.execute("SELECT * FROM logs WHERE timestamp < ?", (cutoff_str,))
        rows = c.fetchall()
        
        if not rows:
            conn.close()
            return # Nothing to archive
            
        print(f"[INFO] Archiving {len(rows)} old logs...")
        
        # 4. Write to CSV
        filename = f"archive_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(archive_dir, filename)
        
        with open(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            # Write Header
            writer.writerow(["ID", "Timestamp", "Src IP", "Dst IP", "Protocol", "Action", "Confidence", "Reason", "PCAP"])
            # Write Data
            writer.writerows(rows)
            
        # 5. Delete from DB
        c.execute("DELETE FROM logs WHERE timestamp < ?", (cutoff_str,))
        
        # 6. Optimize DB (Reclaim space)
        conn.execute("VACUUM")
        
        conn.commit()
        conn.close()
        print(f"[SUCCESS] Logs archived to {filepath}")
        log_system_event("INFO", f"Archived {len(rows)} logs to {filename}")
        
    except Exception as e:
        print(f"[ERROR] Log Rotation Failed: {e}")
        log_system_event("ERROR", f"Log Rotation Failed: {e}")

# Traffic Chart Data
def get_chart_data():
    """
    Returns traffic volume for the last 10 minutes.
    Format: { "labels": ["10:00", "10:01"], "values": [15, 40] }
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        # Group by HH:MM and count rows
        query = """
            SELECT strftime('%H:%M', timestamp) as time_slot, COUNT(*)
            FROM logs
            GROUP BY time_slot
            ORDER BY id DESC
            LIMIT 10
        """
        rows = conn.execute(query).fetchall()
        conn.close()
        
        # SQL returns newest first, so we reverse it for the chart (Left=Old, Right=New)
        rows.reverse()
        
        return {
            "labels": [r[0] for r in rows],
            "values": [r[1] for r in rows]
        }
    except:
        return {"labels": [], "values": []}
    
# --- 🟢 MISSING FUNCTIONS ADDED BELOW ---

def get_recent_logs(limit=50, search_query="", action_filter="ALL"):
    """Fetches the latest logs for the table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        sql = "SELECT * FROM logs WHERE 1=1"
        params = []
        
        if search_query:
            sql += " AND (src_ip LIKE ? OR reason LIKE ?)"
            params.extend([f"%{search_query}%", f"%{search_query}%"])
            
        if action_filter != "ALL":
            sql += " AND action = ?"
            params.append(action_filter)
            
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        
        c.execute(sql, params)
        rows = c.fetchall()
        conn.close()
        
        # Format for API - match the format used by get_logs()
        data = []
        for row in rows:
            data.append({
                "id": row['id'],
                "time": row['timestamp'],
                "src": row['src_ip'],
                "dst": row['dst_ip'],
                "proto": row['protocol'],
                "action": row['action'],
                "conf": row['confidence'],
                "reason": row['reason'],
                "pcap": row['pcap_file']
            })
        return data
    except Exception as e:
        print(f"[DB READ ERROR] {e}")
        return []

def get_dashboard_stats():
    """Returns counts for the dashboard cards."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        stats = {
            "blocked_count": 0,
            "total_events": 0,
            "ai_detections": 0,
            "dpi_alerts": 0,
            "ransomware_detections": 0
        }
        
        # Total Events
        c.execute("SELECT COUNT(*) FROM logs")
        stats["total_events"] = c.fetchone()[0]
        
        # Blocked/Quarantined (Prevention)
        c.execute("SELECT COUNT(*) FROM logs WHERE action IN ('BLOCKED', 'QUARANTINED')")
        stats["blocked_count"] = c.fetchone()[0]
        
        # AI Detections (LSTM Anomalies)
        c.execute("SELECT COUNT(*) FROM logs WHERE reason LIKE '%LSTM%' OR reason LIKE '%Anomaly%'")
        stats["ai_detections"] = c.fetchone()[0]
        
        # DPI Alerts
        c.execute("SELECT COUNT(*) FROM logs WHERE reason LIKE '%DPI%' OR reason LIKE '%SQL%' OR reason LIKE '%XSS%'")
        stats["dpi_alerts"] = c.fetchone()[0]
        
        # Ransomware Detections
        c.execute("SELECT COUNT(*) FROM logs WHERE reason LIKE '%Ransomware%' OR reason LIKE '%Encryption%'")
        stats["ransomware_detections"] = c.fetchone()[0]
        
        conn.close()
        return stats
    except:
        return {"total_threats": 0, "blocked_packets": 0, "active_threats": 0}

def get_graph_data():
    """Returns data points for the Traffic Graph (Last 60 seconds/minutes)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get logs from last 60 seconds grouped by timestamp
        # Using a simple aggregation for demonstration
        now = time.time()
        start_time = now - 60
        
        c.execute("SELECT timestamp FROM logs WHERE timestamp > ?", (start_time,))
        rows = c.fetchall()
        conn.close()
        
        # In a real app, you'd aggregate this into buckets (e.g. per second)
        # For now, return raw timestamps or a simplified list
        return [r[0] for r in rows]
    except:
        return []