# 🔍 CodeAlpha — Advanced Network Sniffer & Traffic Analyzer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge\&logo=python\&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-000000?style=for-the-badge\&logo=flask\&logoColor=white)
![Socket.IO](https://img.shields.io/badge/Socket.IO-4.0%2B-010101?style=for-the-badge\&logo=socketdotio\&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=for-the-badge\&logo=windows\&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

### 🚀 Real-Time Packet Sniffer with Live Web Dashboard, Analytics, Logging & PDF Reporting

**A powerful, cross-platform network packet sniffer and traffic analyzer built using Python, Scapy, Flask, and Socket.IO. Monitor live traffic in real time using both a Command-Line Interface (CLI) and an Interactive Web Dashboard.**

</div>

---

# 📖 Overview

This project is an **advanced real-time network packet sniffer and traffic analyzer** developed as part of the **CodeAlpha Internship Program**.

The system captures live network traffic, analyzes packet structures across multiple **OSI layers**, detects major protocols, applies **Berkeley Packet Filters (BPF)**, generates real-time analytics, and supports exporting logs in multiple formats.

The project supports **two powerful modes**:

## 🖥️ 1. CLI Mode (`main.py`)

A fast, terminal-based packet sniffer featuring:

* 🎨 Color-coded output
* 🔎 Protocol filtering
* 📊 Auto statistics every 15 seconds
* 💾 Multi-format logging (`CSV`, `JSON`, `TXT`)
* ⚡ High-performance BPF filtering

## 🌐 2. Web Dashboard Mode (`web_app.py`)

A modern **localhost-based dashboard** with:

* ▶️ Start packet capture
* ⏹️ Stop capture
* 🔍 Search captured packets
* 📈 Live analytics & protocol charts
* 📄 Download PDF reports
* 📡 Real-time packet streaming using WebSockets

---

# ✨ Features

### 📡 Real-Time Packet Sniffing

Capture live packets directly from the network interface using **Scapy**.

### 🌐 Interactive Web Dashboard

Run:

```bash
python web_app.py
```

Then open:

```txt
http://127.0.0.1:5000
```

Dashboard features:

✅ Start Sniffing
✅ Stop Sniffing
✅ Search Packets
✅ Real-Time Packet Table
✅ Protocol Analytics
✅ Top Source/Destination IP Analysis
✅ Download PDF Report

---

### 🔎 Smart Protocol Detection

The sniffer automatically identifies protocols such as:

* TCP
* UDP
* ICMP
* ARP
* HTTP
* HTTPS
* DNS

---

### 📊 Live Analytics

Built-in analytics include:

* **Protocol Distribution Chart**
* **Top Source IPs**
* **Top Destination IPs**
* **Packet Count Metrics**
* **Real-Time Traffic Insights**

---

### 💾 Multi-Format Logging

Export captured packets into:

| Format | Use Case                     |
| ------ | ---------------------------- |
| CSV    | Excel & Spreadsheet Analysis |
| JSON   | APIs & Data Science          |
| TXT    | Human-readable logs          |

Logs are automatically stored in:

```txt
captures/
```

---

### ⚡ BPF (Berkeley Packet Filter) Support

Efficient packet filtering at the kernel level.

Example filters:

```txt
tcp
udp
icmp
port 80
host 192.168.1.1
```

---

# 🧠 OSI Layer Packet Analysis

The project analyzes packets across multiple layers of the OSI Model.

```txt
┌──────────────────────────────┐
│ Layer 7 → Application Layer  │
│ HTTP / HTTPS / DNS           │
├──────────────────────────────┤
│ Layer 4 → Transport Layer    │
│ TCP / UDP / Ports / Flags    │
├──────────────────────────────┤
│ Layer 3 → Network Layer      │
│ Source IP / Destination IP   │
├──────────────────────────────┤
│ Layer 2 → Data Link Layer    │
│ MAC Address Information      │
└──────────────────────────────┘
```

---

# 📦 Libraries Used

| Library               | Purpose                     |
| --------------------- | --------------------------- |
| `scapy`               | Packet capturing & decoding |
| `flask`               | Web server                  |
| `flask-socketio`      | Real-time communication     |
| `colorama`            | Colored terminal output     |
| `tabulate`            | Statistics tables           |
| `threading`           | Background tasks            |
| `csv`                 | CSV logging                 |
| `json`                | JSON export                 |
| `socket`              | Socket communication        |
| `datetime`            | Timestamp generation        |
| `collections.Counter` | Packet statistics           |

---

# 📋 Requirements

| Requirement | Details                              |
| ----------- | ------------------------------------ |
| Python      | 3.8+                                 |
| Windows     | Run as Administrator                 |
| Linux       | Run using `sudo`                     |
| Npcap       | Required for Windows packet sniffing |

Download Npcap:

https://npcap.com/

---

# 🚀 Installation

## Step 1: Clone Repository

```bash
git clone https://github.com/yourusername/network-sniffer.git
cd network-sniffer
```

## Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

---

# 💻 Running the Project

## 🌐 Run Web Dashboard

### Windows

```powershell
python web_app.py
```

### Linux

```bash
sudo python3 web_app.py
```

Open browser:

```txt
http://127.0.0.1:5000
```

---

## 🖥️ Run CLI Sniffer

```bash
python main.py
```

---

# ⚙️ CLI Options

| Flag     | Description          |
| -------- | -------------------- |
| `-i`     | Network Interface    |
| `-p`     | Protocol Filter      |
| `--ip`   | Filter Specific IP   |
| `--port` | Filter Specific Port |
| `-c`     | Packet Count         |
| `-l`     | Log Format           |

---

# 💡 Command Examples

### Capture all traffic

```bash
python main.py
```

### Capture TCP packets

```bash
python main.py -p tcp
```

### Capture packets from an IP

```bash
python main.py --ip 192.168.1.1
```

### Capture packets on a port

```bash
python main.py --port 80
```

### Capture 100 packets

```bash
python main.py -c 100
```

### Save logs in JSON

```bash
python main.py -l json
```

### Combined Example

```bash
python main.py -i Wi-Fi -p tcp --ip 192.168.1.1 --port 80 -c 50 -l json
```

---

# 📊 Statistics System

Every **15 seconds**, the program automatically generates network statistics including:

* Total Packets
* Protocol Distribution
* Source IP Activity
* Destination IP Activity

Displayed in a clean tabular format using **Tabulate**.

---

# 📤 Terminal Output Format

Example output:

```txt
[TCP] 192.168.1.10:443 → 192.168.1.5:52344
Payload: 512 bytes
Flags: SYN, ACK
```

### Color Meaning

| Color  | Meaning |
| ------ | ------- |
| Green  | TCP     |
| Blue   | UDP     |
| Red    | ICMP    |
| Yellow | DNS     |

---

# 🌐 Web Dashboard Features

| Feature      | Description           |
| ------------ | --------------------- |
| Start        | Start packet capture  |
| Stop         | Stop packet capture   |
| Search       | Search packets        |
| Analytics    | Traffic visualization |
| PDF Export   | Download report       |
| Live Updates | WebSocket streaming   |

---

# 📁 Project Structure

```txt
NETWORK-SNIFFER/
│
├── main.py
├── web_app.py
├── packet_analyzer.py
├── filters.py
├── logger.py
├── statistics.py
├── utils.py
├── requirements.txt
├── README.md
│
├── captures/
│
├── screenshots/
│
├── templates/
│   └── index.html
│
└── static/
    ├── css/
    └── js/
```

---

# 📸 Screenshots

## 🖥️ Terminal Output

```md
<img width="1281" height="943" alt="image" src="https://github.com/user-attachments/assets/8bca7c6f-0852-48a1-9237-c5c5695e78b1" />
<img width="1284" height="958" alt="image" src="https://github.com/user-attachments/assets/174b4818-19b9-4691-9175-2307e51cc8d9" />
```

## 🌐 Web Dashboard

```md
<img width="1918" height="972" alt="image" src="https://github.com/user-attachments/assets/880d6dfc-1400-49a9-a6b5-5d6a4c363382" />
<img width="1919" height="961" alt="image" src="https://github.com/user-attachments/assets/4562acef-9e87-4d11-a399-2214cab7f45c" />
<img width="1000" height="786" alt="image" src="https://github.com/user-attachments/assets/e41bc28f-42c9-4682-986a-7277b07d702d" />
<img width="1005" height="793" alt="image" src="https://github.com/user-attachments/assets/d75c27b8-8292-4a15-b0ec-fa63b3a78f85" />
```

## 📈 Analytics

```md
<img width="1917" height="859" alt="image" src="https://github.com/user-attachments/assets/c05790b4-2cd8-4677-8d65-174ddba96f7a" />
```

---

# 🛠️ Troubleshooting

### Permission Error

Run terminal as **Administrator** (Windows) or use:

```bash
sudo
```

### Scapy Not Found

```bash
pip install scapy
```

### Flask Error

```bash
pip install flask flask-socketio
```

### Dashboard Not Opening

Check:

```txt
http://127.0.0.1:5000
```

---

# ⚠️ Legal Disclaimer

This tool is intended for **educational purposes, internship learning, cybersecurity research, and authorized network monitoring only**.

Do **NOT** use this tool to capture traffic on networks without permission. Unauthorized packet sniffing may violate laws and regulations.

The developer assumes **no responsibility** for misuse.

---

# 👨‍💻 Author

### **Deep Tandel**

**CodeAlpha Internship Project**

GitHub: `https://github.com/DeepTandel045`

---

<div align="center">

### ⭐ If you like this project, consider giving it a star!

Made with ❤️ during the **CodeAlpha Internship Program**

</div>
