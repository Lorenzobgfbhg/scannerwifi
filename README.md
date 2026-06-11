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
* **Auto Interface Detection:** Dynamically detects active local subnets and CIDR blocks using `netifaces`.
* **Data Export:** The latest network audit results can be exported directly into a structured `.csv` file.
* **High Performance:** Maximizes execution speed across large subnets using `ThreadPoolExecutor` (Multi-threading).

---
## ⚙️ How It Works

* **ScannerWifi** works by identifying your active network interface and mapping the local subnet[cite: 1]. It intelligently switches between two scanning methodologies based on system permissions[cite: 1]:.
  
* **ARP Scanning Mode (Sudo/Root)**: Sends standard ARP requests (Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=cidr)) to the broadcast address[cite: 1]. 

* **It captures ARP replies to instantly map IP and MAC addresses with high accuracy, completely bypassing firewall blocks that drop ICMP packets**[cite: 1].

* **Ping Sweep Mode (Standard User)**: Utilizes ThreadPoolExecutor to concurrently send ICMP echo requests (pings) to all potential hosts in the subnet block[cite: 1]. 

* **It then parses the system's local ARP cache table to retrieve MAC addresses where available**[cite: 1].

## 📋 Interactive Menu Guide
* **Upon launch**, you will be prompted with a built-in interactive CLI menu[cite: 1]:
* **Scan entire Wi-Fi network**: Automatically detects your active gateway/subnet and maps all live hosts[cite: 1].
* **Resolve hostname from IP**: Performs interactive Forward/Reverse DNS lookups and checks device latency[cite: 1].
* **Scan details of a single IP + ports**: Probes the host and fingerprints 19 common open ports (SSH, HTTP, SMB, RDP, etc.)[cite: 1].
* **Live network monitor**: Initiates continuous watch-mode to alert you when devices connect [+] or disconnect [-][cite: 1].
* **Display latest scan results**: Prints the last cached scan table back onto the terminal[cite: 1].
Save results to a file: Exports all gathered host metrics into a structured .csv file[cite: 1].

## 🛠️ Technology & Dependencies

* **Python 3.x** — Core programming language.
* **Scapy** — Network packet manipulation and injection (ARP).
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

# Linux / macOS:
Bash
  sudo python3 wifiscanner.py

#Windows (Command Prompt / PowerShell):
Open your terminal as Administrator, then run:
Bash
  python wifiscanner.py
Note: If executed without root/administrator privileges, the tool will gracefully auto-switch to standard Ping Scan mode[cite: 1].
