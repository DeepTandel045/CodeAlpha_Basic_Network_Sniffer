# 🔍 CodeAlpha — Basic Network Sniffer

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D6?style=for-the-badge&logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge)

**A cross-platform packet sniffer written in Python that captures and decodes live network traffic in real time.**

</div>

---

## 📖 Overview

`network_sniffer.py` is a lightweight, cross-platform packet sniffer built with Python for **Windows** and **Linux**. It captures live network traffic using raw sockets, prints decoded packet details directly in the terminal, and can optionally export captures to a JSON file — all without any third-party libraries.

---

## ✨ Features

- 🖥️ **Cross-platform** — Works on both Windows and Linux
- 🔎 **Auto-detection** — Automatically detects the best local interface or IP when none is provided
- 🔀 **Protocol filtering** — Filter traffic by `TCP`, `UDP`, `ICMP`, or capture all packets
- 📋 **Rich packet metadata** — Displays source/destination IPs, ports, TCP flags, TTL, and protocol hints
- 🧾 **Verbose mode** — Hex and ASCII payload dump for deep inspection
- 💾 **JSON export** — Save captured packets to a structured JSON file
- 🎨 **ANSI color output** — Clean, color-coded terminal display with a plain-text fallback
- 📡 **Interface listing** — List all available network interfaces or local IPs

---

## 📋 Requirements

| Requirement | Details |
|---|---|
| Python | 3.8 or newer |
| Windows | Administrator privileges required |
| Linux | Root (`sudo`) privileges required |

> **No third-party packages needed** — uses only Python's standard library.

---

## 🚀 Usage

Run the sniffer from the folder containing the script:

```bash
python network_sniffer.py
```

### 🪟 Windows

Open **Command Prompt** or **PowerShell** as **Administrator**, then run:

```powershell
python network_sniffer.py
```

### 🐧 Linux

Run with `sudo`:

```bash
sudo python3 network_sniffer.py
```

---

## ⚙️ Options

| Flag | Description |
|---|---|
| `-i`, `--interface` | Interface name (Linux) or local IP address (Windows) |
| `-c`, `--count` | Stop after capturing N packets |
| `-f`, `--filter` | Filter by protocol: `tcp`, `udp`, `icmp`, or `all` |
| `-o`, `--output` | Save captured packets to a JSON file |
| `-v`, `--verbose` | Show hex and ASCII payload dump |
| `--no-color` | Disable ANSI color output |
| `--list-interfaces` | Print available interfaces or local IPs and exit |

---

## 💡 Examples

**Capture all packets:**
```bash
python network_sniffer.py
```

**Capture only TCP traffic:**
```bash
python network_sniffer.py -f tcp
```

**Capture 100 packets and stop:**
```bash
python network_sniffer.py -c 100
```

**Save traffic to a JSON file:**
```bash
python network_sniffer.py -o capture.json
```

**Show payload details (verbose mode):**
```bash
python network_sniffer.py -v
```

**Combine multiple options:**
```bash
python network_sniffer.py -f tcp -c 50 -v -o tcp_packets.json
```

**List available interfaces or local IPs:**
```bash
python network_sniffer.py --list-interfaces
```

---

## 📤 Output

Each captured packet is printed with the following details:

| Field | Description |
|---|---|
| `Timestamp` | Time the packet was captured |
| `Protocol` | Detected protocol name (TCP, UDP, ICMP, etc.) |
| `Source IP` | Origin IP address |
| `Destination IP` | Target IP address |
| `Ports` | Source and destination ports (when available) |
| `TCP Flags / ICMP Type` | Flag names or ICMP message type |
| `Payload Size` | Size of the packet payload in bytes |

When **verbose mode** (`-v`) is enabled, the payload is additionally shown as a **hex dump** and a **decoded ASCII preview**.

---

## 📝 Platform Notes

- **Windows** — Uses the local IP address to bind the raw socket and enables receive-all mode (`SIO_RCVALL`).
- **Linux** — Uses an `AF_PACKET` raw socket and can optionally bind to a specific network interface.
- Press **Ctrl+C** to stop the capture at any time, or the sniffer will stop automatically once the `-c` packet count limit is reached.

---

## 📁 Project Structure

```
CodeAlpha_Basic-Network-Sniffer/
│
├── network_sniffer.py   # Main packet sniffer script
└── README.md            # Project documentation
```

---

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized network monitoring only**. Always ensure you have explicit permission before sniffing network traffic. Unauthorized packet capture may violate local laws and regulations.

---

## 🙋‍♂️ Author

**Deep Tandel**
Internship Project — [CodeAlpha](https://www.codealpha.tech/)

---

<div align="center">
  <sub>Made with ❤️ as part of the CodeAlpha Internship Program</sub>
</div>
