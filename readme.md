# 🛡️ Sentinel-X: AI-Powered Next-Gen Hybrid Firewall & EDR System

![Project Status](https://img.shields.io/badge/Status-Active-success)
![Python Version](https://img.shields.io/badge/Python-3.9%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## 📖 Project Overview

**Sentinel-X** is an intelligent, autonomous network security system designed to bridge the gap between traditional rule-based firewalls and modern AI-driven threat detection.

Traditional firewalls often fail to detect sophisticated threats like "Low-and-Slow" DDoS attacks, zero-day exploits, or physical breaches. Sentinel-X solves this by combining **Deep Learning (LSTM)**, **Machine Learning (Random Forest)**, and **Behavioral Heuristics** to detect, block, and report threats in real-time without human intervention.

It transforms a standard defensive setup into a proactive **Endpoint Detection & Response (EDR)** suite, featuring self-healing vulnerability scans, physical port security, and zero-trust architecture.

---

## 🚀 Key Features

### 🧠 **1. Triple-Layer AI Engine**
* **Deep Learning (LSTM):** Analyzes time-series traffic data to detect complex, low-volume anomalies.
* **Machine Learning (Random Forest):** Classifies individual packets based on header features (Size, Flags, Protocol).
* **Phishing Detection:** Real-time URL analysis to block credential harvesting sites.

### 🛡️ **2. Advanced Network Defense**
* **DDoS Protection:** Rate-limiting engine blocks IPs exceeding packet thresholds (e.g., >50 pkts/sec).
* **Deep Packet Inspection (DPI):** Scans payload content for SQL Injection (`' OR 1=1`) and XSS attacks.
* **Zero Trust Architecture:** Scores every connection based on Context (Time, Geo-location, Protocol).
* **DNS Security:** Detects DNS Tunneling (Data Exfiltration) and Sinkholes malicious domains.

### 🔒 **3. Endpoint & Physical Security**
* **Malware Scanner (YARA):** Automatically scans downloaded files against a signature database (e.g., Ransomware, Trojans).
* **USB Sentinel:** Monitors keystroke velocity to detect and lock "Rubber Ducky" attacks.
* **Ransomware Monitor:** Watchdog service that locks the system if rapid file encryption is detected.

### 🏥 **4. Proactive Health (Self-Healing)**
* **Vulnerability Scanner:** Runs daily Nmap scans on the localhost/router to identify open risky ports (e.g., SMB, Telnet) before attackers exploit them.

### 📊 **5. Enterprise Visualization**
* **Real-Time Dashboard:** WebSockets-based UI updating in milliseconds.
* **Voice Alerts:** Text-to-Speech engine announces critical threats audibly (Jarvis-style).
* **PDF Reports:** One-click generation of professional security audit reports.

---

## 🛠️ Technologies Used

* **Language:** Python 3.9+
* **Core Libraries:**
    * `Scapy`: Packet sniffing and manipulation.
    * `TensorFlow/Keras`: Deep Learning (LSTM) models.
    * `Scikit-learn`: Random Forest ML models.
    * `Flask` & `SocketIO`: Web Dashboard and Real-time events.
    * `Pandas` & `NumPy`: Data processing.
    * `YARA-Python`: Malware signature matching.
    * `Python-Nmap`: Network vulnerability scanning.
    * `Watchdog`: File system monitoring.

---

## 🏗️ System Architecture

**Workflow:**
1.  **Ingestion:** Scapy sniffs packets from the network interface.
2.  **Preprocessing:** Features (Size, Protocol, Flags) are extracted and encoded.
3.  **Analysis (Parallel Engines):**
    * *Engine A (Rules):* Checks Blacklists, Geo-IP, and Threat Intel feeds.
    * *Engine B (AI):* Random Forest classifies the packet as Malicious/Benign.
    * *Engine C (Deep Learning):* LSTM checks traffic volume trends.
4.  **Decision:** If any engine flags the packet -> **BLOCK**.
5.  **Response:** Log to DB, Speak Alert, Update Dashboard, Ban IP.

---

## ⚙️ Installation & Setup

### Prerequisites
* **Python 3.9+**
* **Nmap:** Must be installed on the OS and added to system PATH. ([Download Nmap](https://nmap.org/download.html))
* **Admin Privileges:** Required for packet sniffing (Scapy) and USB blocking.

### **1. Clone the Repository**

```bash
git clone [https://github.com/yourusername/sentinel-x.git](https://github.com/yourusername/sentinel-x.git)
cd sentinel-x/nxt
```

### **2️.Create Virtual Environment**

```bash
python -m venv venv

# Windows:
.\venv\Scripts\activate

# Linux/Mac:
source venv/bin/activate
```

### **3️.Install Dependencies**

To install dependencies for the project

```bash
pip install -r requirements.txt
```

### **4️.Train AI Models (First Run Only)**

Initialize the brains of the operation:

```bash
python src/train_model.py       # Random Forest
python src/train_lstm.py        # Deep Learning
python src/train_real_model.py  # Main Anomaly Detector
```

### **🖥️ Usage & Execution**

### Step 1: Start the Admin Server (Optional C2)

```bash
python admin.py
```

### **Step 2: Start Sentinel-X Engine**

* ⚠️ Must run as Administrator/Root

```bash
python app.py
```

### If the project works:

* [INFO] ✅ Sentinel-X Packet AI Loaded Successfully.

### **Step 3: Run Simulations (Test the System)**

* Open a new terminal (Admin) and run the attack suite:

```bash
python attacks/run_all.py
```

* Select Option A to run a Full Stress Test.

### **📂 Project Structure**
nxt/
├── app.py                  # Main Application Entry Point
├── src/
│   ├── firewall.py         # Core Logic (Sniffer + Decision Engine)
│   ├── dl_traffic.py       # Deep Learning (LSTM) Module
│   ├── malware_scanner.py  # YARA Malware Detection
│   ├── usb_defense.py      # Physical USB Security
│   ├── scanner.py          # Proactive Nmap Scanner
│   ├── zero_trust.py       # Zero Trust Scoring
│   └── ...                 # Helper modules (Geo, DNS, Voice, etc.)
├── models/                 # Trained AI Models (.pkl, .h5, .yar)
├── attacks/                # Attack Simulation Scripts (DDoS, SQLi, etc.)
├── templates/              # HTML Dashboard
├── static/                 # CSS/JS Assets
└── logs/                   # Database & Forensic PCAPs

### **🧪 Dataset & Evaluation**

* **Training Data:** Hybrid dataset from NSL-KDD + synthetic traffic (Scapy)

* **Evaluation Methods:** Real-time dashboard for FP/FN feedback loops

* **Forensics:** Blocked packets saved as .pcap for Wireshark

* **Self-Test:** attacks/run_all.py validates each security module

### **⚠️ Limitations**

* Platform: Optimized for Windows

* uses windll + PowerShell context

* Linux requires small locking-mechanism edits

### **Encrypted Traffic:**

* Payload of HTTPS (TLS 1.3) cannot be inspected
* ✔️ Metadata such as SNI, certificates, flow features is analyzed

### **🔮 Future Enhancements**

* Blockchain Logging: Immutable audit trails

* Cloud Integration: Centralized multi-node dashboard

* Reinforcement Learning: Auto-tuning thresholds via feedback