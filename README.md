# 🔍 CodeAlpha — Cybernetic Protocol Intelligence & Network Sniffer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-2.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)
![Socket.io](https://img.shields.io/badge/Socket.io-4.0%2B-010101?style=for-the-badge&logo=socketdotio&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A highly advanced, cross-platform packet sniffer and real-time network traffic analyzer featuring both a professional command-line interface (CLI) and a premium, responsive Web-based Intelligence Dashboard.**

</div>

---

## 📖 Overview

This repository contains the **CodeAlpha Basic Network Sniffer**, which has been engineered into a powerful, dual-interface network analysis suite. Under the hood, it utilizes **Scapy** to hook into network sockets, capture live frames, and perform deep packet inspection across multiple layers of the OSI model.

The application can be operated in two distinct modes:
1. **Interactive Web Dashboard (`web_app.py`)** — A stunning, glassmorphic web dashboard ("Cybernetic Protocol Intelligence") with live packet streams, an interactive OSI-layer decoder, live hex/ASCII payload viewers, dynamic protocol charts, and professional PDF report exports.
2. **Terminal Sniffer Engine (`main.py`)** — A clean, color-coded command-line tool with thread-safe live metrics, customizable Berkeley Packet Filters (BPF), and structured file-logging capabilities (TXT, CSV, JSON).

---

## ✨ Features

### 🖥️ 1. Cybernetic Web Dashboard (`web_app.py`)
- 📡 **Real-time WebSocket Streaming** — Packets are captured at the kernel level and streamed instantaneously to the browser interface via Socket.IO.
- 📈 **Dynamic Visual Analytics** — Live doughnut and horizontal bar charts (powered by Chart.js) tracking protocol distributions and the top active source/destination IP addresses.
- 🔍 **Interactive OSI Layer Dissection** — Click on any packet row to inspect its exact hierarchical layers:
  - **Layer 2 (Data Link)**: Source & Destination MAC addresses.
  - **Layer 3 (Network)**: Source & Destination IP addresses.
  - **Layer 4 (Transport)**: Port numbers, TCP/UDP headers, flags, and types.
  - **Layer 7 (Application)**: Protocol detection (HTTP, HTTPS, DNS) and load decoding.
- 🧾 **Raw Payload Hex Dump** — View side-by-side hexadecimal offsets and ASCII previews of packet data for deep inspection.
- 💾 **Instant PDF Session Exports** — Export a beautifully formatted, dark-themed **Session Capture Report** including statistics, protocol distributions, active charts, and a detailed packet stream log with a single click.
- 🔀 **Active Search and Filters** — Filter packets dynamically as they arrive by searching any property (MAC, IP, Port, Protocol, or payload contents).

### ⚙️ 2. Terminal Sniffer Engine (`main.py`)
- 🎨 **ANSI-colored Console Logs** — Easy-to-read, color-coded protocol tags, addressing indicators (`Source -> Destination`), and payload summaries.
- 🗃️ **Multi-Format Local Logging** — Automatically saves traffic to timestamped files inside the `captures/` folder in your choice of **TXT**, **CSV**, or **JSON** arrays.
- 🔢 **Thread-Safe Metrics Loop** — Spawns a background thread that calculates and outputs tabulate-formatted summary matrices of network metrics every 15 seconds.
- ⚡ **Kernel-Level BPF Filtering** — Filter incoming traffic efficiently at the OS kernel level using standard Berkeley Packet Filters.

---

## 📋 Requirements & Dependencies

The project relies on Python's standard library combined with lightweight, high-performance networking packages:

| Dependency | Purpose | Scope |
|---|---|---|
| `scapy` | Sockets manipulation and packet decoding | Core Engine |
| `flask` | Lightweight Web Server | Web Dashboard |
| `flask-socketio` | Real-time WebSocket communications | Web Dashboard |
| `colorama` | Cross-platform terminal styling | CLI Engine |
| `tabulate` | Terminal metric tables | CLI Engine |

### 🪟 Windows Requirements
- **Npcap** or **WinPcap** must be installed (installed automatically if you have Wireshark, or available from [Npcap.com](https://npcap.com/)).
- Must be executed inside a command window launched with **Administrator privileges**.

### 🐧 Linux Requirements
- Must be executed with **root privileges** (`sudo`) to bind raw network interface sockets.

---

## 🚀 Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/network-sniffer.git
   cd network-sniffer
   ```

2. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 💻 Running the Web Dashboard

To launch the glassmorphic Cybernetic Web Dashboard:

### 🪟 Windows (Run as Administrator)
```powershell
python web_app.py
```

### 🐧 Linux
```bash
sudo python3 web_app.py
```

Once launched, open your web browser and navigate to:
```
http://localhost:5000
```

*In the dashboard, type a BPF filter (e.g. `tcp` or `port 53`), click **Start** to capture live network cards, click on individual packets to dissect them, switch to **Analytics** to view live charts, or click **PDF** to download a professional session report.*

---

## ⚙️ CLI Engine Usage

If you prefer operating inside the terminal, run `main.py`:

```bash
python main.py [options]
```

### Options & Flags

| Flag | Description |
|---|---|
| `-i`, `--interface` | Specific network interface to sniff on (e.g., `'eth0'`, `'Wi-Fi'`) |
| `-p`, `--protocol` | Fast protocol filter shortcut (`tcp`, `udp`, `icmp`, `dns`, `http`, `https`) |
| `--ip` | Filter traffic containing a specific IP (Source or Destination) |
| `--port` | Filter traffic containing a specific Port number |
| `-c`, `--count` | Stop capture automatically after capturing N packets (default: `0` = infinite) |
| `-l`, `--log` | Automatically export captures to `captures/` as `csv`, `json`, or `txt` |

### CLI Examples

**Sniff everything on default interface:**
```bash
python main.py
```

**Filter only TCP traffic and save to a JSON array:**
```bash
python main.py -p tcp -l json
```

**Capture 50 packets on a specific IP address on port 80, then stop:**
```bash
python main.py --ip 192.168.1.100 --port 80 -c 50
```

**Sniff on a specific interface with a CSV log:**
```bash
python main.py -i eth0 -l csv
```

---

## 📁 Project Structure

```
network-sniffer/
│
├── main.py             # CLI Sniffer entry point & BPF assembler
├── web_app.py          # Flask & Socket.IO web server
├── packet_analyzer.py  # OSI layer decoder (Layers 2, 3, 4, and 7 decodes)
├── filters.py          # Berkeley Packet Filter (BPF) filter assembler
├── statistics.py       # Thread-safe packet counters and metrics
├── logger.py           # Multi-format logger (CSV, JSON, TXT)
├── utils.py            # CLI visual assets and banner printing
├── requirements.txt    # Project dependencies
│
├── templates/
│   └── index.html      # Responsive glassmorphic dashboard frontend
│
├── static/
│   ├── css/
│   │   └── style.css   # Dark cybersecurity dashboard theme
│   └── js/
│       └── app.js      # Socket.IO client, Chart.js engine & jsPDF report builder
│
└── README.md           # Documentation
```

---

## ⚠️ Disclaimer

This tool is designed for **educational purposes, academic research, and authorized administrative network monitoring** only. Sniffing traffic on networks without prior written permission is illegal in many jurisdictions. The author and CodeAlpha accept no responsibility for unauthorized or malicious use of this software.

---

## 🙋‍♂️ Author

**Deep Tandel**
Internship Project — [CodeAlpha](https://www.codealpha.tech/)

---

<div align="center">
  <sub>Made with ❤️ as part of the CodeAlpha Internship Program</sub>
</div>
