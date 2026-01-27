from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import sqlite3
import os
import threading
import time
import requests 
from src.socket_handler import socketio


# --- INTERNAL MODULE IMPORTS ---
# We consolidate all imports from src to avoid duplicates and circular errors
from src.database import (
    init_db, get_logs, get_system_logs, get_stats, 
    get_system_status, get_whitelist, add_whitelist, 
    remove_whitelist, get_setting, update_setting, 
    log_system_event, DB_PATH, add_custom_rule, get_custom_rules,
    delete_custom_rule, archive_old_logs, get_chart_data, 
    get_dashboard_stats, get_recent_logs, get_graph_data
)
from src.firewall import start_firewall
from src.ransomware import start_ransomware_monitor
from src.phising import check_url_safety
from src.honeypot import start_honeypot  
from src.firewall import refresh_firewall_rules
from src.feedback import add_feedback_entry
from src.integrity import start_integrity_monitor 
from src.protected_server import start_protected_server
from src.reports import generate_pdf_report
from src.layer2 import start_malware_monitor
from src.usb_defense import start_usb_sentinel
from src.scanner import start_vulnerability_scanner


# 1. Global Cache
ip_cache = {}

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sentinel_secret_key'
CORS(app)

socketio.init_app(app)


# --- UTILITY FUNCTIONS ---

def get_location(ip):
    """Translates an IP address to [Lat, Lon] using ip-api.com."""
    if ip.startswith("192.168.") or ip.startswith("127.") or ip.startswith("10."):
        return None
    
    if ip in ip_cache:
        return ip_cache[ip]
    
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
        if data['status'] == 'success':
            location_data = {
                "lat": data['lat'], 
                "lon": data['lon'], 
                "info": f"{data['city']}, {data['country']}"
            }
            ip_cache[ip] = location_data
            return location_data
    except:
        pass
    return None

# --- ROUTES ---

# Network Graph Data
@app.route('/api/graph_data')
def graph_data():
    logs = get_logs()
    nodes = []
    edges = []
    
    # Add Localhost (Center Node)
    nodes.append({"id": "You", "label": "Sentinel-X", "color": "#66fcf1", "shape": "hexagon", "size": 30})
    
    unique_ips = set()
    for log in logs:
        ip = log['src']
        if ip not in unique_ips:
            # Determine color based on action
            color = "#ff4d4d" if log['action'] == "BLOCKED" else "#4caf50"
            nodes.append({"id": ip, "label": ip, "color": color, "shape": "dot"})
            unique_ips.add(ip)
            
        # Add Edge
        edges.append({"from": ip, "to": "You", "color": "#45a29e"})
        
    return jsonify({"nodes": nodes, "edges": edges})

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/api/stats')
def stats():
    return jsonify(get_dashboard_stats())

@app.route('/system_logs')
def system_logs_page():
    logs = get_system_logs()
    return render_template('system_logs.html', logs=logs)

@app.route('/settings')
def settings_page():
    return render_template('settings.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/api/feedback/false_positive', methods=['POST'])
def report_false_positive():
    """
    Receives packet features from the frontend to mark as Safe.
    Expected JSON: {"src_bytes": 123, "proto": 1, "service": 2, "flag": 0}
    """
    data = request.json
    try:
        # Extract features in correct order
        features = [
            int(data.get('src_bytes')),
            int(data.get('proto')),
            int(data.get('service')),
            int(data.get('flag'))
        ]
        
        # Add to separate dataset & trigger separate training
        add_feedback_entry(features)
        
        return jsonify({"status": "success", "message": "Feedback recorded. Model retrained."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    

# --- API ENDPOINTS ---

@app.route('/api/data')
def api_data():
    """Feeds the Dashboard with real-time logs and stats."""
    # 1. Get Filters from URL Query String
    search_q = request.args.get('search', '')
    action_f = request.args.get('action', 'ALL')

    # 2. Pass them to DB
    logs = get_recent_logs(limit=50, search_query=search_q, action_filter=action_f)
    stats = get_dashboard_stats()  # Use the correct function
    is_online = get_system_status()

    # Process Map Markers
    map_markers = []
    processed_ips = set()
    for log in logs:
        src_ip = log['src']  # Fixed: use correct key name from get_recent_logs
        if src_ip not in processed_ips:
            loc = get_location(src_ip)
            if loc:
                map_markers.append({
                    "lat": loc["lat"],
                    "lon": loc["lon"],
                    "ip": src_ip,
                    "info": loc["info"],
                    "type": log['action']
                })
            processed_ips.add(src_ip)

    return jsonify({
        "logs": logs, 
        "stats": stats,
        "chart_data": get_chart_data(),
        "status": "ONLINE" if is_online else "OFFLINE"
    })

@app.route('/check_url', methods=['POST'])
def check_url():
    """AI Phishing Detection."""
    url = request.json.get('url', '')
    is_phishing, conf, reason = check_url_safety(url)
    return jsonify({
        "is_phishing": is_phishing, 
        "confidence": f"{conf*100:.1f}%", 
        "reason": reason
    })

@app.route('/api/settings', methods=['GET', 'POST'])
def handle_settings():
    if request.method == 'GET':
        return jsonify({
            "blocking_mode": get_setting("blocking_mode", "ON"),
            "sensitivity": get_setting("sensitivity", "0.80")
        })
    if request.method == 'POST':
        data = request.json
        update_setting("blocking_mode", data.get("blocking_mode"))
        update_setting("sensitivity", data.get("sensitivity"))
        return jsonify({"status": "updated"})

@app.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
def manage_rules():
    if request.method == 'GET':
        return jsonify(get_whitelist())
    if request.method == 'POST':
        add_whitelist(request.json.get('ip'))
        return jsonify({"status": "added"})
    if request.method == 'DELETE':
        remove_whitelist(request.json.get('ip'))
        return jsonify({"status": "removed"})
    return jsonify({"error": "Invalid request"}), 400


# --- DOWNLOADS ---

@app.route('/download_report')
def download_report_route():
    try:
        path = generate_pdf_report()
        return send_file(path, as_attachment=True)
    except Exception as e:
        return f"Error generating PDF: {e}", 500

@app.route('/api/rules', methods=['GET', 'POST', 'DELETE'])
def manage_custom_rules():
    if request.method == 'GET':
        return jsonify(get_custom_rules())
    
    if request.method == 'POST':
        # Add new rule
        data = request.json
        r_type = data.get('type')  # "IP" or "PORT"
        value = data.get('value')
        
        if r_type and value:
            add_custom_rule(r_type, value)
            # TRIGGER IMMEDIATE UPDATE IN FIREWALL
            refresh_firewall_rules()
            return jsonify({"status": "added", "rule": f"{r_type} : {value}"})

    if request.method == 'DELETE':
        # Remove rule
        data = request.json
        rule_id = data.get('id')
        if rule_id:
            delete_custom_rule(rule_id)
            # TRIGGER IMMEDIATE UPDATE
            refresh_firewall_rules()
            return jsonify({"status": "deleted"})

    return jsonify({"error": "Invalid request"}), 400

def maintenance_loop():
    """Checks for old logs once every 24 hours"""
    while True:
        # Archive logs older than 30 days (Adjust as needed)
        archive_old_logs(retention_days=360)
        
        # Sleep for 24 hours (86400 seconds)
        time.sleep(86400)


# --- STARTUP ---

def start_background_services():
    print("[INFO] 🚀 Initializing Sentinel-X Services...")
    # 1. Initialize Database
    init_db()
    
    # 2. Start Self-Defense (Integrity Check) - Run this FIRST
    start_integrity_monitor()  
    
    #Layer 1

    # 3. Start Ransomware Monitor
    threading.Thread(target=start_ransomware_monitor, args=(None,), daemon=True).start()

    # 4. Start Firewall Sniffer
    threading.Thread(target=start_firewall, daemon=True).start()

    # 5. Start Honeypot Trap (Port 2323)
    threading.Thread(target=start_honeypot, daemon=True).start()

    # Layer 2

    # Start ARP Spoofing Monitor
    # threading.Thread(target=start_arp_monitor, daemon=True).start()

    # ... (Protected Server, Maintenance Loop) ...
    # 6. Start Protected Gateway (The "Real" Server on Port 8080)
    threading.Thread(target=start_protected_server, daemon=True).start()

    # Start YARA Malware Scanner
    threading.Thread(target=start_malware_monitor, daemon=True).start()

    # Start Physical Port Security
    threading.Thread(target=start_usb_sentinel, daemon=True).start()

    # Start Vulnerability Scanner
    threading.Thread(target=start_vulnerability_scanner, daemon=True).start()

    print("[INFO] ✅ All Sentinel-X Services are Online.")

    threading.Thread(target=maintenance_loop, daemon=True).start()

if __name__ == '__main__':
    start_background_services()
    print("🚀 Sentinel-X Dashboard running with WebSockets...")
    # Use socketio.run instead of app.run
    socketio.run(app, host='0.0.0.0', port=5000, debug=False, allow_unsafe_werkzeug=True)