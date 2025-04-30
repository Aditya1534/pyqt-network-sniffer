# 🛡️ Packet Sniffer & Injector GUI Tool (PyQt5 + Scapy)

This is a Python-based **network packet sniffer and injector GUI tool** built with **PyQt5** and **Scapy**. It allows you to sniff live network traffic, analyze packet details (including HTTP, HTTPS, TCP, UDP), **inject crafted packets**, and **export data** for further analysis.

---

## 📦 Features

✅ Live packet capture of:
- **TCP**, **UDP**, **HTTP**, **HTTPS** packets  
- Displays **source**, **destination**, **protocol**, **length**, and **info** fields in a readable format  
- Detects and highlights raw payloads (including basic malicious patterns)

✅ Packet injection support:
- Custom protocol selection (TCP/UDP)
- Destination IP and payload selector (e.g., SQL injection, XSS)
- Real-time log of injected packets

✅ Export capabilities:
- Export captured packets to **CSV** and **YAML** formats

✅ GUI-based:
- User-friendly **PyQt5 interface** with dropdowns for IPs, protocol, payload, and logs
- Auto-refreshing IP selector from captured traffic

✅ Start/Stop controlled sniffing

---

## 🔓 Decryption Feature (Optional / Planned)

If encrypted packets are captured (e.g., HTTPS), payloads may not be readable. If TLS decryption is possible (e.g., using mitmproxy or imported keys), future versions will attempt to:

- **Decrypt HTTPS traffic**
- **Log sensitive fields** (login, passwords, API tokens)
- **Alert on malicious keywords**

This part requires secure handling of keys and ethical usage.

---

## 🧠 Why This Tool is Unique

> Most packet sniffers are either terminal-based or too complex for basic analysis and injection. This tool is:

- **Beginner-friendly** with GUI controls
- Combines **sniffing + injection** + **real-time logging**
- Export in multiple formats (CSV, YAML)
- Ready for **threat simulation** (XSS, SQLi test payloads)
- Modular for **researchers** and **cybersecurity students**
- Extensible: future features like traffic graphs, alert systems, and anomaly detection

---

## 💡 Benefits

- Great for **learning and teaching** network protocols
- Simulate basic **attack payloads** in a controlled environment
- Quickly filter, export, and review traffic for security research
- Can be integrated into **larger vulnerability scanners**
- Lightweight and doesn't require root for most features

---

## 🛠️ Requirements

- Python 3.x
- PyQt5
- scapy
- pyyaml

Install with:
```bash
pip install pyqt5 scapy pyyaml
