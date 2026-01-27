🛡️ Sentinel-X: AI-Driven Next-Gen Firewall
SIH 2025 Submission | Problem Statement ID: 25160 Advanced Encrypted Traffic Analysis & Zero Trust Enforcement

📖 Overview
Sentinel-X is a comprehensive, hybrid cybersecurity platform that combines Machine Learning, Deep Packet Inspection (DPI), and Deception Technology to detect and block sophisticated network threats.

It features a real-time "Cyberpunk" style dashboard for monitoring traffic, managing rules, and visualizing attacks.

🚀 Key Features
🧠 Hybrid Detection Engine: Combines Random Forest AI (for anomaly detection) with Static Rules.

🔍 Deep Packet Inspection (DPI): Scans packet payloads for SQL Injection and XSS attacks.

🍯 Honeypot Trap: Exposes fake vulnerable ports (Port 2323) to entrap and flag attackers.

🌍 Geo-Blocking: Automatically blocks traffic from high-risk countries.

🦠 Ransomware Protection: Monitors file systems for rapid encryption behavior (watchdog).

⛔ Dynamic Rule Engine: Add/Remove blocking rules (IPs/Ports) via the Dashboard without restarting.

🎣 AI Phishing Detector: Scans URLs using machine learning to detect malicious links.

📊 Advanced Dashboard: Features Dark/Light mode, Interactive Charts, Maps, and Search Filtering.

📂 Project Structure
Plaintext

nxt/
│
├── app.py                   # 🧠 MAIN CONTROLLER: Web Server & Service Orchestrator
├── admin.py                 # 👑 C2 SERVER: Receives critical alerts from the firewall
├── requirements.txt         # 📦 Dependencies
├── README.md                # 📄 Documentation
│
├── src/                     # ⚙️ CORE LOGIC
│   ├── firewall.py          # Main Packet Sniffer (Multiprocessing)
│   ├── dpi.py               # Deep Packet Inspection (SQLi/XSS)
│   ├── honeypot.py          # Deception Module (Fake Port Listener)
│   ├── geo.py               # IP-to-Country Blocking Logic
│   ├── ransomware.py        # File Integrity Monitor
│   ├── database.py          # SQLite Handler (WAL Mode enabled)
│   ├── phising.py           # Phishing URL Detector
│   ├── reports.py           # PDF Report Generator
│   ├── train_model.py       # Trainer for Phishing Model
│   └── train_real_model.py  # Trainer for Network AI Model
│
├── Attack/                  # ⚔️ ATTACK SIMULATIONS
│   ├── fastflood.py         # DDoS Simulation
│   ├── ransomware_sim.py    # Ransomware Simulation
│   ├── suspicious_port.py   # Port Beaconing
│   ├── large_payloads.py    # Buffer Overflow / Anomalous Payload
│   ├── test_dpi.py          # SQL Injection Test
│   ├── test_honeypot.py     # Honeypot Connection Test
│   └── test_geo.py          # Geo-Blocking Test
│
├── models/                  # 🤖 AI MODELS
│   ├── nsl_kdd_data.csv     # (Dataset)
│   ├── real_firewall_brain.pkl  # (Trained Network Model)
│   └── phishing_model.pkl       # (Trained Phishing Model)
│
├── logs/                    # 🗄️ LOGS & DATABASE
│   └── firewall_logs.db     # Main Database
│
├── static/                  # 🎨 ASSETS (CSS, JS)
└── templates/               # 🖥️ HTML UI
⚡ Installation & Setup
1. Prerequisites
Python 3.9+

Windows Users: Install Npcap (Select "Install in WinPcap API-compatible Mode").

Linux Users: Run sudo apt install libpcap-dev.

2. Install Dependencies
Open a terminal in the nxt/ folder:

Bash

pip install -r requirements.txt
3. Train the AI Brains (Crucial Step)
You must generate the AI models before running the app.

Bash

# Train Phishing Detector
python src/train_model.py

# Train Network Traffic Analyzer
python src/train_real_model.py
Wait for the "✅ SUCCESS" message for both.

🚦 Execution Guide
Step 1: Start the Admin Server (Optional but Recommended)
This acts as the "Command & Control" center for receiving critical alerts. Open Terminal 1:

Bash

python admin.py
URL: http://127.0.0.1:5001

Step 2: Start the Main Firewall System
This launches the Dashboard, Sniffer, Ransomware Monitor, and Honeypot. Note: Run as Administrator (Windows) or sudo (Linux).

Open Terminal 2:

Bash

python app.py
URL: http://127.0.0.1:5000

You should see logs indicating "Sniffer Started", "Honeypot Active", "Ransomware Monitor Watching".

🧪 How to Test (Attack Simulations)
Open Terminal 3 to run these attacks. Watch the Main Dashboard to see them being blocked in real-time.

1. Test DDoS / Flood Detection
Sends high-frequency packets to trigger the volume-based blocker.

Bash

python Attack/fastflood.py
2. Test Ransomware Protection
Rapidly creates encrypted files in the protected folder.

Bash

python Attack/ransomware_sim.py
3. Test Deep Packet Inspection (SQL Injection)
Sends a malicious payload (' OR 1=1) inside a packet.

Bash

python Attack/test_dpi.py
4. Test Honeypot Trap
Attempts to connect to the fake Port 2323.

Bash

python Attack/test_honeypot.py
5. Test Large Payload Anomaly
Sends a packet larger than the standard MTU (2000+ bytes).

Bash

python Attack/large_payloads.py
6. Test Suspicious Port Beaconing
Attempts to connect to non-standard port 9999.

Bash

python Attack/suspicious_port.py
🛠️ Dashboard & Configuration
Accessing the UI
Go to http://127.0.0.1:5000.

Customizing the Firewall
Navigate to the Settings page:

Sensitivity Slider: Adjust how aggressive the AI is (0.5 = Balanced, 0.9 = Strict).

Blocking Mode: Toggle between "Monitor Only" (Log) and "Active Defense" (Block).

Dynamic Rules: Manually add an IP (e.g., 192.168.1.50) or Port (e.g., 8080) to the blacklist. Takes effect immediately.

Viewing Logs
Live Table: Shows the latest 50 packets.

Search/Filter: Use the search bar to find specific IPs or filter by "BLOCKED" only.

Map: Visualizes the geolocation of threats.

Charts: View traffic volume trends over the last 10 minutes.