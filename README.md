# 📡 ScannerWifi — Advanced Wi-Fi & Local Network Auditor

`ScannerWifi` is a Python 3-based CLI tool designed to scan, analyze, and monitor devices within a private Wi-Fi network in real-time. This project serves as my **main project** to deepen my Python programming skills, focusing on network packet manipulation (network engineering) and network auditing.

The tool is smartly designed with a dual-mode scanning architecture: it utilizes high-performance **ARP Requests (Scapy)** when executed with Administrator/Root privileges, and automatically falls back to a multi-threaded **Ping Sweep** when run in standard user mode.

> **⚠️ Disclaimer:** This tool is strictly developed for educational purposes, cybersecurity learning, and authorized personal network analysis. Unauthorized network scanning or any misuse is entirely the responsibility of the end-user.

---

## 🚀 Key Features

* **Dual-Mode Scan Engine:** Supports ultra-fast scanning powered by *ARP Broadcasts* (Scapy) as well as adaptive subnet discovery via *ICMP Ping*.
* **Smart Network Discovery:** Displays a comprehensive mapping of IP addresses, Hostnames (*Reverse DNS lookup*), MAC addresses, latency levels (ms), and automatic device Vendor identification based on a built-in OUI database.
* **Interactive Sub-Tools Integration:**
  * **Hostname Resolver:** Provides in-depth forward/reverse DNS analysis and looks up aliases for a specific IP.
  * **Port Scanner:** Probes 19 of the most crucial and common network ports (such as SSH, FTP, HTTP, HTTPS, SMB, RDP, etc.) on a targeted host.
  * **Live Network Monitor:** A continuous *watch-mode* feature that automatically detects and alerts you with visual notifications when a new device joins `[+]` or leaves `[-]` the network.
* **Auto Interface Detection:** Dynamically detects active local subnets and CIDR blocks using `netifaces`[cite: 1].
* **Data Export:** The latest network audit results can be exported directly into a structured `.csv` file[cite: 1].
* **High Performance:** Maximizes execution speed across large subnets using `ThreadPoolExecutor` (Multi-threading)[cite: 1].

---

## 🛠️ Technology & Dependencies

* **Python 3.x** — Core programming language[cite: 1].
* **Scapy** — Network packet manipulation and injection (ARP)[cite: 1].
* **Netifaces** — Network Interface Card (NIC) information gathering[cite: 1].
* **Tabulate** — Text-based table rendering for a clean and precise CLI layout[cite: 1].

---

## 📋 Installation Guide

Before running `ScannerWifi`, ensure you have Python 3 and the required third-party libraries installed[cite: 1].

```bash
# Clone this repository
git clone [https://github.com/Lorenzobgfbhg/scannerwifi.git](https://github.com/Lorenzobgfbhg/scannerwifi.git)

# Navigate into the project directory
cd scannerwifi

# Install the required dependencies
pip install scapy netifaces tabulate
