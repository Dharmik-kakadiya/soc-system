# 🛡️ Responsive SOC (Intrusion Detection & Prevention System)

Welcome to the **Responsive SOC (Security Operations Center)**! This project is an end-to-end, machine-learning-powered network security system designed to monitor live traffic, detect malicious attacks in real-time, and take automated defensive actions.

## 🎯 What does this system do?
This system acts as a digital security guard for your network/computer. Its primary purposes are:
1. **Live Network Monitoring:** It silently listens to incoming and outgoing network traffic.
2. **Threat Detection (AI/ML):** It passes network statistics through trained Machine Learning models to identify cyber attacks (e.g., DDoS, DoS, BruteForce, Infiltration, and Botnets) with high accuracy.
3. **Automated Response (IPS):** Depending on the severity of the threat, it can automatically log the event, flag the IP, or actively block the attacker using Windows Firewall.
4. **Visual Analytics:** It provides a beautiful, real-time dashboard to visualize what is happening on your network.

---

## 🏗️ System Architecture & Components

The system is fully modular and composed of several independent components orchestrated together:

### 1. 📡 Live Packet Sniffer (`scripts/sniffer.py`)
- Uses `scapy` to capture raw network packets.
- Extracts complex flow features on-the-fly (e.g., Packets per second, Bytes per second, max/min packet lengths).
- Sends optimized JSON payloads to the ML API for prediction without blocking the sniffing process.

### 2. 🧠 ML Inference Engine (`api/main.py` & `ml/pipeline/predict.py`)
- A highly concurrent `FastAPI` backend.
- Uses `scikit-learn` models (Random Forest) and feature scaling to classify traffic into specific attack vectors.
- Exposes a `/predict` endpoint for the sniffer and a `/health` endpoint for system orchestration.

### 3. 🚨 Alert & Response Manager (`ml/alerts/alert_manager.py`)
- **Anti-Spam Cooldown:** Prevents terminal and log spam by enforcing a 30-second cooldown per (IP + Attack Type).
- **Whitelist:** Ensures safe internal IPs (like `127.0.0.1` or `192.168.1.1`) are never blocked.
- **Dynamic Severity Mapping:** 
  - `LOW` → Safe/Minor issues (Logged)
  - `MEDIUM` / `HIGH` → DDoS/BruteForce (Flagged)
  - `CRITICAL` → Infiltration/Bots (Actively Blocked)
- **Auto-Unblock System:** Automatically adds a Windows Firewall rule to block critical IPs, and safely deletes the rule after 60 seconds.

### 4. 📊 Live Dashboard (`dashboard/app.py`)
- Built with `Streamlit`.
- Features zero-dependency pure HTML/SVG charts for fast rendering.
- Automatically deduplicates logs so you only see unique threats in the Live Alerts Feed.
- Shows total threats, unique attackers, severity badges, and automated actions taken by the system.

### 5. ⚙️ Robust Orchestrator (`scripts/run_soc.py`)
- Acts as the master controller.
- Validates system paths, boots the API, waits for successful HTTP health checks, and then securely launches the Dashboard and Sniffer.
- Continuously monitors child processes. If any process crashes, it triggers a safe, graceful shutdown of the entire system.

### 6. 🧪 Attack Simulator (`scripts/simulate_attack.py`)
- A safe testing utility to inject dummy attack records into the system to verify that the Dashboard and Response Manager are working correctly.

---

## 🚀 How to Use the System

### Prerequisites
- Python 3.x installed.
- Administrative (Elevated) privileges are required to run the network sniffer and manipulate the Windows Firewall.

### Starting the SOC System
1. Open a terminal as **Administrator**.
2. Navigate to the project root directory.
3. Run the orchestration script:
   ```bash
   python scripts/run_soc.py
   ```
4. The script will automatically:
   - Start the FastAPI server on port `8001`.
   - Open the Streamlit Dashboard in your default web browser (usually at `http://localhost:8501` or `8502`).
   - Start listening to network traffic.

### Testing the System
If you don't have active malicious traffic but want to see the dashboard in action:
1. Keep the SOC system running.
2. Open a second terminal.
3. Run the simulator:
   ```bash
   python scripts/simulate_attack.py
   ```
4. Check your Dashboard! You will see alerts pop up and observe the Firewall blocking actions in real-time.

### Stopping the System
- Simply press `Ctrl + C` in the main terminal. The orchestrator will catch the interrupt and cleanly shut down the API, Dashboard, and Sniffer processes.

---

## 🛡️ Security Disclaimer
This tool actively manipulates Windows Firewall rules. The auto-unblock system will remove rules after 60 seconds, but always exercise caution when testing the `CRITICAL` blocking features on a production network. The whitelist feature ensures your local machine stays accessible.
