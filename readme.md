# 🛡️ Sentinel-X: AI Hybrid Firewall & EDR Command Center

**Sentinel-X** is an intelligent, autonomous Endpoint Detection and Response (EDR) suite and packet-filtering firewall designed to defend enterprise networks. By combining a **Triple-Layer AI Engine**, deep packet payloads scans, zero-trust contextual filters, hardware port surveillance, and automatic directory guardians, it seals vulnerabilities before exploits can start.

The system is designed with a **decoupled full-stack architecture**, featuring a fast C-based packet sniffer backend (Flask API + Scapy) and a high-end, responsive Next.js dashboard UI.

---

## 🚀 Key Feature Categories

### 🧠 1. Triple-Layer AI Analysis
*   **Machine Learning Classifiers:** Evaluates raw TCP/UDP packet headers (flags, ports, bytes) in microseconds using a highly trained Random Forest model.
*   **Deep Learning Volume Forecaster:** Sequential time-series forecasting utilizing a **Keras LSTM** model to predict expected traffic levels, flagging zero-day network abnormalities.
*   **Explainable URL Phishing Scan:** Parses Unicode patterns, homograph brand mimicking, domain age, WHOIS logs, and SSL attributes through a Random Forest pipeline.

### 🛡️ 2. Advanced Active Defenses
*   **DDoS Flow Limiter:** Automatic, high-performance packet velocity filter that locks out flooding IPs (exceeding >50 pkts/sec) instantly.
*   **Deep Packet Inspection (DPI):** Scans raw packet payloads for SQL Injection signatures and Cross-Site Scripting (XSS) payloads.
*   **Zero-Trust Context Scoring:** Evaluates a trust score (0–100) dynamically based on geographic country codes, protocol suitability, and access hours.
*   **DNS Tunneling & Sinkhole:** Detects Shannon Entropy leaks inside subdomains and sinkholes malicious requests using fake resolver packets.
*   **Global Threat Feeds:** Dynamic, hourly atomic updates syncing with Emerging Threats and Feodo Tracker C2 blocklists.

### 🔒 3. Host & Physical EDR Protections
*   **YARA Malware Scanner:** Watchdog system that matches newly downloaded files against compiled malware signature rule blocks.
*   **Ransomware Directory Guardian:** Monitors modification thresholds inside protected vaults, locking the workstation if rapid encryption is detected.
*   **Keystroke USB Sentinel:** Hooks global keyboards to detect superhuman typing velocity (delays <50ms) to quarantine Rubber Ducky USB injections.
*   **Self-Defense Integrity Watchdog:** Hashes and monitors all core codebase source files via SHA-256 on startup to protect the firewall software itself against tampering or unauthorized modifications.

### 🏥 4. Proactive Diagnostics & Decoys
*   **Self-Healing Vulnerability Scanner:** Initiates daily automated Nmap sweeps on local routes to audit exposed protocols (SMB, Telnet, MySQL) and reports them on the command panel.
*   **Interactive Decoy Honeypot:** Spawns mock target listeners (SSH, HTTP, Telnet) on inactive ports to attract, detect, and analyze scanner sweeps and brute-force sweeps.

### 🕵️‍♂️ 5. Forensics & Automated Reporting
*   **Real-time PCAP Forensic Captures:** Automatically captures and exports raw packet sequences in PCAP format when high-severity DPI signatures are triggered.
*   **PDF Forensic Reports:** Generates professional, styled PDF logs summarizing firewall blocks, system resource metrics, and threat profiles for network audits.
*   **Audible Voice Warning System:** Integrates dynamic Text-to-Speech (TTS) vocal warnings to instantly alert system administrators audibly to critical breaches.

### 🕸️ 6. Interactive Network Visualization & Feedback
*   **Live Threat Topology Map:** Uses a client-side canvas-based graph rendering interface (powered by `vis-network`) to map out IP addresses forwarding traffic to your computer. Threatening IPs are dynamically updated and visually isolated/color-coded based on block or alert status.
*   **User Feedback Learning Overrides:** Enables administrator overriding of false positives directly from the log console. It trains a secondary machine learning model that dynamically permits legitimate overridden traffic streams.

---

## 🏗️ Decoupled Full-Stack Architecture

Sentinel-X operates as a decoupled system:
1.  **Backend C2 Sniffer (`app.py` - Port 5000):** Consists of a multi-processed architecture. A dedicated sniffer process intercepts packets bypassing the Python GIL, pushing raw logs to a main analyzer consumer thread. Exposes REST APIs and emits websocket alerts.
2.  **Next.js Dashboard (`/frontend` - Port 3000):** Built on React, TypeScript, and Tailwind CSS. Connects to Flask using Socket.IO and maps telemetry charts cleanly.

---

## 📂 Simplified Folder Structure
```
fullnxt/
├── backend/                    # Backend C2 Sniffer (Flask API + Scapy)
│   ├── app.py                  # Flask API & Sniffer Engine Entry (Port 5000)
│   ├── admin.py                # Mock C2 Control Panel
│   ├── requirements.txt        # Python Core Library Manifest
│   ├── src/                    # Active Sniffers & Defensive Modules
│   │   ├── firewall.py         # Packet Classifier & Core Analyzer Loops
│   │   ├── database.py         # Fully Parameterized SQLite Logs Engine
│   │   ├── dl_traffic.py       # Keras LSTM Anomaly Predictor
│   │   ├── zero_trust.py       # Zero-Trust Context Scorer
│   │   ├── cnn_gru_inference.py # Hybrid Sequence Classification
│   │   └── ...                 # Helper utilities (DPI, DNS, Geo, Voice)
│   ├── models/                 # Trained Machine Learning & YARA Signature Files
│   ├── attacks/                # Simulation Attack Suite Scripts
│   └── logs/                   # SQLite Database Logs & Forensic PCAP folder
└── frontend/                   # Decoupled Next.js TypeScript Dashboard (Port 3000)
```

---

## ⚙️ Installation & Bootstrapping

### Prerequisites
*   **Nmap:** Must be installed on your OS and added to system PATH variables.
*   **Elevated Shell:** Packet sniffing interfaces (Scapy) and keyboard hooks require Administrator/Root permissions.

### Step 1: Start the Backend Sniffer (Elevated Terminal)
```bash
# 1. Navigate to the backend directory
cd backend

# 2. Create and activate environment
python -m venv venv
.\venv\Scripts\activate

# 3. Install requirements
pip install -r requirements.txt

# 4. Boot Flask C2 Engine
$env:PYTHONIOENCODING="utf-8"
python app.py
```

### Step 2: Start the Next.js Dashboard
```bash
# Open a new terminal
cd frontend
npm install
npm run dev
```
Open **[http://127.0.0.1:3000](http://127.0.0.1:3000)** in your browser!

---

## 🧪 Diagnostic Stress-Testing Scenarios

Run the attack diagnostic panel to verify active defense blocking:
```bash
cd backend
python attacks/run_all.py
```

*   **Option A**: *Full Stress Test* - Sweeps across large buffer overflows, non-standard beaconing, and DDoS floods.
*   **YARA Test**: Drop any signature rule file into `backend/Simulated_Downloads/` to verify quarantine movements.
*   **Zero-Trust Test**: Connect to Port `8080` (Mock Corporate Gateway) to check dynamic trust scoring.