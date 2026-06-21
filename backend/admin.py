from flask import Flask, render_template, jsonify, request
import datetime

app = Flask(__name__)

# Data Stores (In-memory for Admin demo)
agents = {} 
alerts = []
chat_messages = []


@app.route('/')
def dashboard():
    return render_template('admin_dashboard.html')

@app.route('/api/agents')
def get_agents():
    """Return all registered agents"""
    result = {}
    for ip, data in agents.items():
        result[ip] = {
            "status": data['status'],
            "last_seen": data['last_seen'].strftime("%Y-%m-%d %H:%M:%S")
        }
    return jsonify(result)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    agents[data['ip']] = {"status": "Online", "last_seen": datetime.datetime.now()}
    return jsonify({"status": "Registered"})

@app.route('/api/alert', methods=['POST'])
def receive_alert():
    data = request.json
    alert = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "source": data.get("source"),
        "message": data.get("message"),
        "type": "CRITICAL"
    }
    alerts.insert(0, alert)
    return jsonify({"status": "Received"})

@app.route('/api/alerts', methods=['GET'])
def get_alerts():
    """Return all alerts (sorted by most recent first)"""
    return jsonify(alerts)

@app.route('/api/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        msg = request.json
        chat_messages.append({"sender": "Admin", "text": msg['text'], "time": datetime.datetime.now().strftime("%H:%M")})
        return jsonify({"status": "Sent"})
    return jsonify(chat_messages)

# --- DEMO DATA FOR TESTING ---
def initialize_demo_data():
    """Populates admin console with sample data for testing"""
    global agents, alerts
    
    # Add sample agents
    agents["192.168.1.100"] = {"status": "Online", "last_seen": datetime.datetime.now()}
    agents["192.168.1.101"] = {"status": "Online", "last_seen": datetime.datetime.now()}
    agents["10.0.0.50"] = {"status": "Offline", "last_seen": datetime.datetime.now() - datetime.timedelta(hours=2)}
    
    # Add sample alerts
    alerts = [
        {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "source": "192.168.1.50",
            "message": "SQL Injection Attempt Detected",
            "type": "CRITICAL"
        },
        {
            "time": (datetime.datetime.now() - datetime.timedelta(minutes=5)).strftime("%H:%M:%S"),
            "source": "10.0.0.200",
            "message": "DDoS Attack - 120 pps from this IP",
            "type": "CRITICAL"
        },
        {
            "time": (datetime.datetime.now() - datetime.timedelta(minutes=15)).strftime("%H:%M:%S"),
            "source": "172.16.0.10",
            "message": "Malware Detected - Ransomware Signature Match",
            "type": "CRITICAL"
        }
    ]

if __name__ == '__main__':
    initialize_demo_data()
    print("👑 Admin C2 Server Running on Port 5001")
    print("📊 Demo data initialized with sample agents and alerts")
    app.run(port=5001, debug=True)