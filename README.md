# 🛡️ SOC System — AI-Powered Intrusion Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?logo=fastapi)
![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-red?logo=streamlit)
![ML](https://img.shields.io/badge/ML-RandomForest-orange?logo=scikit-learn)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?logo=windows)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

**A real-time, AI-powered Security Operations Center that monitors live network traffic, detects cyber attacks, and automatically responds to threats.**

</div>

---

## 🎯 What Does This System Do?

This system acts as a digital security guard for your Windows computer/network:

1. **📡 Live Network Monitoring** — Silently captures and analyzes incoming/outgoing traffic
2. **🧠 AI Threat Detection** — Uses trained ML models (Random Forest) to identify attacks like DDoS, BruteForce, Infiltration, and Botnets
3. **🚨 Automated Response (IPS)** — Automatically logs, flags, or **blocks** malicious IPs using Windows Firewall
4. **📊 Real-Time Dashboard** — Beautiful live dashboard showing threats, attacker IPs, and actions taken

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────┐
│                   run_soc.py                        │
│              (Master Orchestrator)                  │
└────────┬──────────────┬──────────────┬──────────────┘
         │              │              │
         ▼              ▼              ▼
   ┌──────────┐  ┌────────────┐  ┌──────────────┐
   │  FastAPI │  │  Sniffer   │  │  Streamlit   │
   │  :8001   │  │ (scapy)    │  │  Dashboard   │
   └──────────┘  └────────────┘  └──────────────┘
         ▲              │
         │   POST /predict
         └──────────────┘
              ML Models
         (RandomForest + Scaler)
```

### Components

| Component | File | Description |
|-----------|------|-------------|
| 🎛️ Orchestrator | `scripts/run_soc.py` | Starts all services, monitors health |
| 📡 Sniffer | `scripts/sniffer.py` | Captures packets, extracts 78 features |
| 🧠 ML API | `api/main.py` | FastAPI inference engine |
| 🚨 Alert Manager | `ml/alerts/alert_manager.py` | Logs, flags, and blocks threats |
| 📊 Dashboard | `dashboard/app.py` | Real-time Streamlit UI |
| 🧪 Attack Simulator | `scripts/simulate_attack.py` | Test without real attacks |

---

## ⚡ Quick Start

### Prerequisites

| Requirement | Details |
|-------------|---------|
| **OS** | Windows 10/11 (Required for Firewall integration) |
| **Python** | 3.8 or higher |
| **Npcap** | Required for packet sniffing → [Download here](https://npcap.com/#download) |
| **Admin rights** | Required to sniff packets and modify Firewall |
| **ML Models** | See [Training Models](#-training-the-models) below |

### Installation

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/Dharmik-kakadiya/soc-system.git
cd soc-system
```

**Step 2 — Install Npcap:**
- Download from: https://npcap.com/#download
- During install, check **"Install Npcap in WinPcap API-compatible Mode"**

**Step 3 — Run the setup script (as Administrator):**
```bash
setup.bat
```

Or manually install dependencies:
```bash
pip install -r requirements.txt
```

**Step 4 — Train the ML models:**
```bash
python scripts/train_attack_model.py
python scripts/train_ids_model.py
```
> ⚠️ You need the CIC-IDS2017 dataset. See [Training Models](#-training-the-models) for details.

### Running the SOC System

Open a terminal **as Administrator** and run:
```bash
python scripts/run_soc.py
```

The system will automatically:
- ✅ Start the FastAPI server on port `8001`
- ✅ Start the Network Sniffer
- ✅ Open the Streamlit Dashboard at `http://localhost:8501`

### Testing Without Real Attacks

Keep the SOC running, then in a **second terminal**:
```bash
python scripts/simulate_attack.py
```
Watch alerts appear live on the dashboard! 🎯

### Stopping the System
Press `Ctrl + C` in the main terminal — all services shut down cleanly.

---

## 🧠 Training the Models

The ML models are trained on the **CIC-IDS2017** dataset by the Canadian Institute for Cybersecurity.

1. **Download the dataset**: [UNB CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
2. Place CSV files in the `data/` directory
3. Run:
```bash
python scripts/prepare_dataset.py     # Prepare & clean data
python scripts/train_attack_model.py  # Train attack classifier
python scripts/train_ids_model.py     # Train IDS model
python scripts/build_preprocessors.py # Build scalers/encoders
```

Models will be saved to `ml/models/`.

---

## 🚨 Threat Severity & Actions

| Severity | Attack Types | Action Taken |
|----------|-------------|--------------|
| 🟡 LOW | Minor anomalies | Logged only |
| 🟠 MEDIUM | DoS, Port Scans | Logged + Flagged |
| 🔴 HIGH | DDoS, BruteForce | Flagged |
| 🚨 CRITICAL | Infiltration, Botnets | **Auto-blocked via Firewall** (60s) |

> Auto-blocked IPs are automatically **unblocked after 60 seconds**. Your local IP is always whitelisted.

---

## 📁 Project Structure

```
soc-system/
├── api/                    # FastAPI backend
│   ├── main.py
│   └── routes/
│       ├── health.py
│       └── predict.py
├── dashboard/
│   └── app.py              # Streamlit dashboard
├── ml/
│   ├── alerts/
│   │   └── alert_manager.py
│   ├── models/             # Trained .pkl models (not in git)
│   ├── preprocessors/      # Scalers/encoders
│   └── pipeline/
│       ├── predict.py
│       └── preprocess.py
├── scripts/
│   ├── run_soc.py          # ⭐ Main entry point
│   ├── sniffer.py
│   ├── train_attack_model.py
│   ├── train_ids_model.py
│   └── simulate_attack.py
├── data/                   # Place dataset CSVs here
├── requirements.txt
├── setup.bat
└── config.py
```

---

## 🛠️ API Reference

Once running, visit: **http://127.0.0.1:8001/docs** (auto-generated Swagger UI)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Check if API is live |
| `/predict` | POST | Submit flow features for threat classification |

---

## ⚠️ Security Disclaimer

- This tool **actively modifies Windows Firewall rules**
- Always test in a **controlled/isolated environment** first
- The auto-unblock system removes rules after 60 seconds
- Your local machine IPs are always whitelisted
- **Use responsibly and only on networks you own/have permission to monitor**

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<div align="center">
Built with ❤️ | SOC System v1.0
</div>
