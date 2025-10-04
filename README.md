# 🛡️ Advanced Simple IDS (Intrusion Detection System)

A lightweight yet **advanced Intrusion Detection System (IDS)** built in **Python** using **Scapy**.  
It monitors live network traffic and detects suspicious activities or attacks such as:

- SYN flood / repeated TCP connection attempts  
- ICMP (ping) flood  
- Port scanning behavior  
- Payload signature matching (regex)  
- Optional Slack and Email alerts  
- Optional auto-blocking via `iptables` (safe dry-run by default)

> ⚠️ **Legal Notice:**  
> This project is for **educational and authorized testing** only.  
> Never run it on networks or systems you don’t own or have permission to test.

---

## 📖 Table of Contents

1. [Project Overview](#project-overview)  
2. [Features](#features)  
3. [Requirements](#requirements)  
4. [Installation](#installation)  
5. [Quick Start](#quick-start)  
6. [Configuration File](#configuration-file)  
7. [Signatures File](#signatures-file)  
8. [Command-Line Usage Examples](#command-line-usage-examples)  
9. [Logging and Alerts](#logging-and-alerts)  
10. [Auto-Blocking](#auto-blocking)  
11. [Run as a systemd Service](#run-as-a-systemd-service)  
12. [Folder Structure](#folder-structure)  
13. [Upload to GitHub](#upload-to-github)  
14. [Tips and Best Practices](#tips-and-best-practices)  
15. [Contributing](#contributing)  
16. [License](#license)  
17. [Help & Support](#help--support)

---

## 🧩 Project Overview

**Advanced Simple IDS** is a Python-based network monitoring tool that helps detect common intrusion patterns.  
It works by analyzing network traffic using **Scapy** and applying detection rules for:
- Flooding attacks (SYN, ICMP)
- Port scans
- Custom regex-based signatures

This project is designed for educational use, penetration testing labs, and basic network monitoring.

---

## ✨ Features

- ✅ Real-time traffic monitoring using Scapy  
- ✅ Detects TCP/ICMP floods and port scans  
- ✅ Custom payload signature detection via regex  
- ✅ Slack & Email notifications  
- ✅ Auto-blocking using iptables (optional)  
- ✅ Configurable via YAML file  
- ✅ Detailed rotating log system  
- ✅ Modular design for easy extension

---

## ⚙️ Requirements

- **Python 3.8+**
- Dependencies:
  - `scapy`
  - `pyyaml`
  - `requests`
- **Linux/macOS:** Run as root for packet sniffing and iptables  
- **Windows:** Install **NPcap** or **WinPcap**, then run as Administrator

---

## 💾 Installation

1. Clone or download this repository.
   ```bash
   git clone https://github.com/YOUR_USERNAME/advanced-ids.git
   cd advanced-ids
   
## 🚀 Quick Start

Get the IDS running in just a few steps.

1. **Create a Python virtual environment and install dependencies**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install --upgrade pip
   pip install scapy pyyaml requests
Identify the network interface to monitor
```
ip link show
or
ifconfig -a
```

Run the IDS
```
sudo python3 simple_ids.py -i <interface>
Example:
sudo python3 simple_ids.py -i eth0
```

(Optional) Use a YAML configuration file
```
sudo python3 simple_ids.py -i eth0 -c ids_config.yaml
```

Tip: Start with block_dry_run: true in the config to avoid accidental blocking while you validate alerts.

🧰 Usage Examples
---

Examples showing common ways to run the tool:

Simple run (default thresholds):
```
sudo python3 simple_ids.py -i eth0
```

Run with a configuration file:
```
sudo python3 simple_ids.py -i eth0 -c ids_config.yaml
```

Use a BPF filter to reduce captured traffic:
```
sudo python3 simple_ids.py -i eth0 --bpf "tcp or icmp"
```


Override thresholds via CLI (if supported):
```
sudo python3 simple_ids.py -i eth0 --syn-threshold 50 --icmp-threshold 150 --window 15
```

Run in foreground and pipe logs:
```
sudo python3 simple_ids.py -i eth0 -c ids_config.yaml 2>&1 | tee ids_runtime.log
```
