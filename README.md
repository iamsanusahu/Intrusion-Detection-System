# 🚨 Intrusion Detection System (Python + Scapy)

A simple yet powerful Python-based **Intrusion Detection System (IDS)** that monitors live network traffic and detects potential threats using signature-based rules.

---

## 📌 Features

- 🕵️ Detects suspicious IP addresses or ports
- 💡 Alerts in real-time and saves logs
- 💾 Lightweight, no database required
- 🖥️ Works on **Windows** (with Npcap) and **Linux**
- 🔧 Easily customizable `rules.json` configuration

---

## 📂 Project Structure

network-ids/
├── ids.py # Main IDS script
├── rules.json # JSON rule definitions
├── alerts.log # Auto-created alert log
├── requirements.txt # Python dependencies
├── LICENSE # MIT license
└── README.md # You're reading this!

yaml
Copy
Edit

---

## 🔧 Installation (Windows)

### 1. Install Python:
👉 [https://www.python.org/downloads](https://www.python.org/downloads)

✅ Check “Add to PATH” during install.

### 2. Install Dependencies:
```bash
pip install -r requirements.txt
3. Install Npcap:
👉 https://nmap.org/npcap

✅ Check: Install in WinPcap API-compatible mode

🚀 Running the IDS
Open Command Prompt in the project directory:

bash
Copy
Edit
python ids.py
If a rule is matched, the alert is printed and saved to alerts.log:

csharp
Copy
Edit
[ALERT] [2025-06-14 18:35:12] Suspicious IP detected: 192.168.1.100 from 192.168.1.100 to 10.0.0.1
⚙️ Editing Rules
In rules.json, you can define rules like:

json
Copy
Edit
{ "type": "ip", "ip": "192.168.1.100" }
{ "type": "port", "port": 4444 }
📜 License
This project is licensed under the MIT License — free to use, modify, and distribute.

🙋 About the Project
This was created as part of my 1-Month Cybersecurity Internship Project (Task 3) under CodeC Technologies.

Connect with me on LinkedIn: https://linkedin.com/in/yourname

yaml
Copy
Edit

---
