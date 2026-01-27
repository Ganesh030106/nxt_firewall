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

@app.route('/api/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        msg = request.json
        chat_messages.append({"sender": "Admin", "text": msg['text'], "time": datetime.datetime.now().strftime("%H:%M")})
        return jsonify({"status": "Sent"})
    return jsonify(chat_messages)

if __name__ == '__main__':
    print("👑 Admin C2 Server Running on Port 5001")
    app.run(port=5001, debug=True)