#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         WiFi Network Scanner  —  Python Edition             ║
║   Scan device, IP, Hostname, MAC & Port di jaringan lokal   ║
╚══════════════════════════════════════════════════════════════╝
Penulis : WiFiScanner Tool
Require : python3, scapy, netifaces  (pip install scapy netifaces)
Catatan : Jalankan dengan sudo untuk ARP scan yang akurat
"""

import os
import sys
import socket
import struct
import threading
import subprocess
import ipaddress
import time
import platform
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# ── Cek dan import library opsional ──────────────────────────────────────────
try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False

try:
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0          # silent scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ── Warna ANSI ────────────────────────────────────────────────────────────────
R   = "\033[0m"
RED = "\033[31m"
GRN = "\033[32m"
YLW = "\033[33m"
BLU = "\033[34m"
PRP = "\033[35m"
CYN = "\033[36m"
WHT = "\033[37m"
BLD = "\033[1m"

# ── Database OUI (vendor) ─────────────────────────────────────────────────────
OUI_DB = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "AC:84:C6": "Apple",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "18:FE:34": "Espressif (ESP8266)",
    "AC:67:B2": "Espressif (ESP32)",
    "CC:50:E3": "Espressif",
    "24:6F:28": "Espressif",
    "00:1B:63": "Apple",
    "00:23:12": "Apple",
    "40:4D:7F": "Samsung",
    "70:F1:A1": "Samsung",
    "18:29:9E": "Xiaomi",
    "64:09:80": "Xiaomi",
    "A4:C1:38": "Telink",
    "00:1E:58": "D-Link",
    "1C:7E:E5": "TP-Link",
    "54:AF:97": "TP-Link",
    "50:3E:AA": "TP-Link",
    "EC:08:6B": "TP-Link",
    "00:14:BF": "Linksys",
    "00:18:39": "Cisco",
    "00:1D:70": "Cisco",
    "F8:1A:67": "ASUS",
    "00:E0:4C": "Realtek",
    "D4:6D:50": "Huawei",
    "00:25:9C": "Cisco/Meraki",
    "4C:ED:FB": "Dell",
    "00:21:CC": "Intel",
    "8C:8D:28": "Intel",
}

PORT_NAMES = {
    21:   "FTP",
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    135:  "RPC",
    139:  "NetBIOS",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5000: "UPnP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}

COMMON_PORTS = sorted(PORT_NAMES.keys())

# ═════════════════════════════════════════════════════════════════════════════
#  Fungsi Utilitas
# ═════════════════════════════════════════════════════════════════════════════

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def banner():
    print(f"""
{CYN}{BLD}╔══════════════════════════════════════════════════════════════╗
║         WiFi Network Scanner  —  Python Edition             ║
║   Scan device, IP, Hostname, MAC & Port di jaringan lokal   ║
╚══════════════════════════════════════════════════════════════╝{R}
  {GRN}[✓]{R} Platform  : {platform.system()} {platform.release()}
  {GRN}[✓]{R} Python    : {sys.version.split()[0]}
  {GRN}[✓]{R} Scapy ARP : {"Aktif" if HAS_SCAPY else f"{YLW}Tidak tersedia (mode ping){R}"}
  {GRN}[✓]{R} Waktu     : {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
""")

def lookup_vendor(mac: str) -> str:
    if not mac or mac == "N/A":
        return "Unknown"
    prefix = mac.upper()[:8]
    return OUI_DB.get(prefix, "Unknown")

def resolve_hostname(ip: str, timeout: float = 3.0) -> str:
    """Reverse DNS lookup."""
    old = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host = socket.gethostbyaddr(ip)[0]
        return host if host else "N/A"
    except Exception:
        return "N/A"
    finally:
        socket.setdefaulttimeout(old)

def ping_host(ip: str) -> tuple[bool, float]:
    """Ping satu host, return (online, latency_ms)."""
    flag = "-n" if platform.system() == "Windows" else "-c"
    wait  = "-w" if platform.system() == "Windows" else "-W"
    t0 = time.time()
    try:
        r = subprocess.run(
            ["ping", flag, "1", wait, "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2
        )
        ms = (time.time() - t0) * 1000
        return r.returncode == 0, round(ms, 1)
    except Exception:
        return False, 0.0

def get_arp_table() -> dict[str, str]:
    """Baca tabel ARP sistem, return {ip: mac}."""
    result = {}
    try:
        out = subprocess.check_output(
            ["arp", "-a" if platform.system() == "Windows" else "-n"],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode(errors="ignore")
        pattern = re.compile(
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+([0-9a-fA-F:]{11,17})"
        )
        for m in pattern.finditer(out):
            result[m.group(1)] = m.group(2).upper()
    except Exception:
        pass
    return result

def check_port(ip: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except Exception:
        return False

# ═════════════════════════════════════════════════════════════════════════════
#  Deteksi Interface & Subnet
# ═════════════════════════════════════════════════════════════════════════════

def get_local_subnets() -> list[dict]:
    """Kembalikan list interface aktif beserta CIDR-nya."""
    found = []
    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for entry in addrs[netifaces.AF_INET]:
                ip  = entry.get("addr", "")
                nm  = entry.get("netmask", "")
                if not ip or ip.startswith("127."):
                    continue
                try:
                    net = ipaddress.IPv4Network(f"{ip}/{nm}", strict=False)
                    found.append({"iface": iface, "ip": ip, "cidr": str(net)})
                except Exception:
                    pass
    else:
        # fallback: hostname
        try:
            ip = socket.gethostbyname(socket.gethostname())
            if not ip.startswith("127."):
                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                found.append({"iface": "eth?", "ip": ip, "cidr": str(net)})
        except Exception:
            pass
    return found

# ═════════════════════════════════════════════════════════════════════════════
#  Scan Subnet — dua metode
# ═════════════════════════════════════════════════════════════════════════════

def _scapy_arp_scan(cidr: str) -> list[dict]:
    """ARP scan pakai Scapy — lebih akurat, butuh root."""
    print(f"  {BLU}[~]{R} Menggunakan ARP scan (Scapy)…")
    pkt  = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    ans, _ = srp(pkt, timeout=3, retry=1, verbose=False)
    devices = []
    for _, rcv in ans:
        devices.append({
            "ip":  rcv.psrc,
            "mac": rcv.hwsrc.upper(),
        })
    return devices

def _ping_scan(cidr: str, workers: int = 100) -> list[dict]:
    """Ping scan — tidak butuh root, lebih lambat."""
    net    = ipaddress.IPv4Network(cidr, strict=False)
    hosts  = [str(h) for h in net.hosts()]
    total  = len(hosts)
    print(f"  {YLW}[*]{R} Ping scan {total} host dengan {workers} worker…")

    results = []
    lock    = threading.Lock()
    counter = [0]

    def task(ip):
        ok, ms = ping_host(ip)
        with lock:
            counter[0] += 1
            pct = counter[0] / total * 100
            print(f"\r  {BLU}[~]{R} Progress: {counter[0]}/{total}  ({pct:.0f}%)", end="", flush=True)
        if ok:
            with lock:
                results.append({"ip": ip, "mac": None, "latency": ms})

    with ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(task, hosts))
    print()
    return results

def scan_network(cidr: str, workers: int = 100) -> list[dict]:
    """
    Scan subnet dan kembalikan list device lengkap.
    Prioritas: Scapy ARP → fallback ping.
    """
    t0 = time.time()
    raw = []

    if HAS_SCAPY and os.geteuid() == 0:
        try:
            raw = _scapy_arp_scan(cidr)
        except Exception as e:
            print(f"  {YLW}[!]{R} ARP scan gagal ({e}), fallback ke ping…")
            raw = _ping_scan(cidr, workers)
    else:
        if HAS_SCAPY:
            print(f"  {YLW}[!]{R} Scapy tersedia tapi tidak root — pakai ping scan.")
        raw = _ping_scan(cidr, workers)

    # Ambil ARP table sistem untuk MAC (khusus ping-scan)
    arp_table = get_arp_table()

    # Resolve hostname + MAC + vendor
    print(f"  {YLW}[*]{R} Resolving hostname untuk {len(raw)} device…")
    devices = []

    def enrich(entry):
        ip  = entry["ip"]
        mac = entry.get("mac") or arp_table.get(ip, "N/A")
        if mac and mac != "N/A":
            mac = mac.upper()
        lat = entry.get("latency", 0.0)
        if lat == 0.0 and not entry.get("mac"):
            _, lat = ping_host(ip)
        return {
            "ip":       ip,
            "hostname": resolve_hostname(ip),
            "mac":      mac or "N/A",
            "vendor":   lookup_vendor(mac or ""),
            "latency":  lat,
        }

    with ThreadPoolExecutor(max_workers=50) as ex:
        futs = {ex.submit(enrich, e): e for e in raw}
        for f in as_completed(futs):
            try:
                devices.append(f.result())
            except Exception:
                pass

    # Urutkan berdasarkan IP
    devices.sort(key=lambda d: socket.inet_aton(d["ip"]))
    elapsed = time.time() - t0
    return devices, elapsed

# ═════════════════════════════════════════════════════════════════════════════
#  Tampilan Tabel
# ═════════════════════════════════════════════════════════════════════════════

def print_devices(devices: list[dict]):
    if not devices:
        print(f"\n  {RED}[!]{R} Tidak ada device ditemukan.\n")
        return

    rows = []
    for i, d in enumerate(devices, 1):
        host = d["hostname"]
        if len(host) > 30:
            host = host[:27] + "…"
        vendor = d["vendor"]
        if len(vendor) > 16:
            vendor = vendor[:13] + "…"
        status_color = GRN if d["hostname"] != "N/A" else YLW
        rows.append([
            f"{i}",
            f"{GRN}{d['ip']}{R}",
            f"{status_color}{host}{R}",
            d["mac"],
            vendor,
            f"{d['latency']:.1f} ms",
        ])

    headers = [
        f"{BLD}No{R}", f"{BLD}IP Address{R}", f"{BLD}Hostname{R}",
        f"{BLD}MAC Address{R}", f"{BLD}Vendor{R}", f"{BLD}Latency{R}"
    ]

    if HAS_TABULATE:
        print("\n" + tabulate(rows, headers=headers, tablefmt="╒═╤═╕"))
    else:
        # Fallback manual
        w = [4, 15, 30, 18, 16, 10]
        sep = "├" + "┼".join("─" * (n + 2) for n in w) + "┤"
        def row_fmt(cols):
            return "│ " + " │ ".join(str(c).ljust(w[i]) for i, c in enumerate(cols)) + " │"
        print("\n╒" + "╤".join("═" * (n + 2) for n in w) + "╕")
        print(row_fmt(["No", "IP Address", "Hostname", "MAC Address", "Vendor", "Latency"]))
        print(sep)
        for r in rows:
            print(row_fmt(r))
        print("╘" + "╧".join("═" * (n + 2) for n in w) + "╛")

    print(f"\n  {GRN}[✓]{R} Total device online: {BLD}{len(devices)}{R}\n")

# ═════════════════════════════════════════════════════════════════════════════
#  Sub-Tool 1: Resolusi Hostname
# ═════════════════════════════════════════════════════════════════════════════

def subtool_resolve():
    print(f"""
{CYN}{BLD}╔══════════════════════════════════════════════════════╗
║       Sub-Tool: Resolusi Hostname dari IP            ║
║   Masukkan IP untuk melihat nama host secara detail  ║
╚══════════════════════════════════════════════════════╝{R}
  Ketik IP lalu Enter. Ketik {YLW}q{R} untuk kembali.
""")
    arp_table = get_arp_table()

    while True:
        try:
            raw = input(f"  {YLW}IP >> {R}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if raw.lower() in ("q", "quit", "exit", ""):
            break
        try:
            socket.inet_aton(raw)
        except socket.error:
            print(f"  {RED}[!]{R} IP tidak valid, coba lagi.\n")
            continue

        ip = raw
        print(f"  {BLU}[~]{R} Resolving {ip} …")
        t0 = time.time()

        # 1. Reverse DNS
        try:
            names = socket.gethostbyaddr(ip)
            hostname_main = names[0]
            aliases       = names[1]
        except Exception:
            hostname_main = "N/A"
            aliases       = []

        # 2. Forward DNS dari hostname
        forward_ips = []
        if hostname_main != "N/A":
            try:
                info = socket.getaddrinfo(hostname_main, None)
                forward_ips = list({r[4][0] for r in info})
            except Exception:
                pass

        # 3. ARP
        mac    = arp_table.get(ip, "N/A")
        vendor = lookup_vendor(mac)

        # 4. Ping latency
        online, latency = ping_host(ip)
        elapsed = (time.time() - t0) * 1000

        status = f"{GRN}ONLINE{R}" if online else f"{RED}OFFLINE{R}"

        print(f"""
  {GRN}┌─ Hasil Resolusi ─────────────────────────────────────────{R}
  {GRN}│{R}  IP Address    : {BLD}{ip}{R}
  {GRN}│{R}  Status        : {status}
  {GRN}│{R}  Hostname      : {BLD}{hostname_main}{R}""")

        if aliases:
            print(f"  {GRN}│{R}  Alias         : {', '.join(aliases)}")
        if forward_ips:
            print(f"  {GRN}│{R}  Forward IP    : {', '.join(forward_ips)}")

        print(f"  {GRN}│{R}  MAC Address   : {mac}")
        print(f"  {GRN}│{R}  Vendor        : {vendor}")
        if online:
            print(f"  {GRN}│{R}  Latency       : {latency:.1f} ms")
        print(f"  {GRN}│{R}  Waktu resolve  : {elapsed:.1f} ms")
        print(f"  {GRN}└─────────────────────────────────────────────────────────{R}\n")

# ═════════════════════════════════════════════════════════════════════════════
#  Sub-Tool 2: Scan Detail Satu IP
# ═════════════════════════════════════════════════════════════════════════════

def subtool_detail():
    print(f"""
{CYN}{BLD}╔══════════════════════════════════════════════════════╗
║      Sub-Tool: Scan Detail Satu IP Address           ║
║   Ping + Hostname + MAC + Port scan                  ║
╚══════════════════════════════════════════════════════╝{R}
  Ketik IP lalu Enter. Ketik {YLW}q{R} untuk kembali.
""")
    arp_table = get_arp_table()

    while True:
        try:
            raw = input(f"  {YLW}IP >> {R}").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if raw.lower() in ("q", "quit", "exit", ""):
            break
        try:
            socket.inet_aton(raw)
        except socket.error:
            print(f"  {RED}[!]{R} IP tidak valid.\n")
            continue

        ip = raw
        print(f"\n  {BLU}[~]{R} Scanning {ip} …")

        # Ping
        online, latency = ping_host(ip)
        status = f"{GRN}ONLINE ✓{R}" if online else f"{RED}OFFLINE ✗{R}"

        # Hostname
        hostname = resolve_hostname(ip) if online else "N/A"

        # MAC
        mac    = arp_table.get(ip, "N/A")
        vendor = lookup_vendor(mac)

        # Port scan
        open_ports = []
        if online:
            print(f"  {BLU}[~]{R} Scanning {len(COMMON_PORTS)} port umum …", end="", flush=True)
            lock = threading.Lock()

            def scan_port(p):
                if check_port(ip, p, timeout=0.6):
                    with lock:
                        open_ports.append(p)

            with ThreadPoolExecutor(max_workers=30) as ex:
                list(ex.map(scan_port, COMMON_PORTS))
            open_ports.sort()
            print(f"\r  {BLU}[~]{R} Port scan selesai.           ")

        # Tampilkan
        print(f"""
  {GRN}┌─ Detail Host ──────────────────────────────────────────{R}
  {GRN}│{R}  IP Address    : {BLD}{ip}{R}
  {GRN}│{R}  Status        : {status}
  {GRN}│{R}  Hostname      : {BLD}{hostname}{R}
  {GRN}│{R}  MAC Address   : {mac}
  {GRN}│{R}  Vendor        : {vendor}""")

        if online:
            print(f"  {GRN}│{R}  Latency       : {latency:.1f} ms")
        if open_ports:
            port_str = "  ".join(
                f"{BLD}{p}{R}/{PORT_NAMES.get(p, '?')}" for p in open_ports
            )
            print(f"  {GRN}│{R}  Port Terbuka  : {port_str}")
        elif online:
            print(f"  {GRN}│{R}  Port Terbuka  : (tidak ada port umum)")

        print(f"  {GRN}└──────────────────────────────────────────────────────{R}\n")

# ═════════════════════════════════════════════════════════════════════════════
#  Sub-Tool 3: Live Monitor (watch mode)
# ═════════════════════════════════════════════════════════════════════════════

def subtool_monitor():
    print(f"""
{CYN}{BLD}╔══════════════════════════════════════════════════════╗
║      Sub-Tool: Live Monitor Jaringan                 ║
║   Scan berulang, tampilkan device baru/hilang        ║
╚══════════════════════════════════════════════════════╝{R}""")

    subnets = get_local_subnets()
    if not subnets:
        print(f"  {RED}[!]{R} Tidak ada subnet terdeteksi.\n")
        return

    for i, s in enumerate(subnets, 1):
        print(f"  {i}. {s['iface']:12} {s['ip']:16} → {CYN}{s['cidr']}{R}")

    try:
        idx = int(input(f"\n  {YLW}Pilih subnet [1-{len(subnets)}]: {R}").strip()) - 1
        cidr = subnets[idx]["cidr"]
        interval = int(input(f"  {YLW}Interval scan (detik) [default 30]: {R}").strip() or "30")
    except (ValueError, IndexError, EOFError):
        print(f"  {RED}[!]{R} Input tidak valid.\n")
        return

    known = set()
    print(f"\n  {GRN}[✓]{R} Monitor {CYN}{cidr}{R} setiap {interval} detik. Ctrl+C untuk berhenti.\n")

    try:
        while True:
            t = datetime.now().strftime("%H:%M:%S")
            print(f"  {BLU}[{t}]{R} Scanning…", end="", flush=True)

            if HAS_SCAPY and os.geteuid() == 0:
                raw = _scapy_arp_scan(cidr)
                current = {d["ip"] for d in raw}
            else:
                net   = ipaddress.IPv4Network(cidr, strict=False)
                hosts = [str(h) for h in net.hosts()]
                current = set()
                lock = threading.Lock()
                def _p(ip):
                    ok, _ = ping_host(ip)
                    if ok:
                        with lock:
                            current.add(ip)
                with ThreadPoolExecutor(max_workers=100) as ex:
                    list(ex.map(_p, hosts))

            new_dev  = current - known
            gone_dev = known   - current

            print(f"\r  {BLU}[{t}]{R} Online: {GRN}{len(current)}{R} device", end="")

            if new_dev:
                for ip in sorted(new_dev):
                    h = resolve_hostname(ip)
                    print(f"\n  {GRN}[+] BARU  {R} {BLD}{ip:16}{R}  {h}")
            if gone_dev:
                for ip in sorted(gone_dev):
                    print(f"\n  {RED}[-] PERGI {R} {ip}")
            if not new_dev and not gone_dev:
                print("  (tidak ada perubahan)", end="")
            print()

            known = current
            time.sleep(interval)
    except KeyboardInterrupt:
        print(f"\n\n  {YLW}[!]{R} Monitor dihentikan.\n")

# ═════════════════════════════════════════════════════════════════════════════
#  Menu Utama
# ═════════════════════════════════════════════════════════════════════════════

def main_menu():
    banner()
    last_devices = []

    while True:
        print(f"""{PRP}{BLD}
  ╔══════════════════════════════════════════╗
  ║              MENU UTAMA                  ║
  ║  1. Scan seluruh jaringan WiFi           ║
  ║  2. Resolusi hostname dari IP            ║
  ║  3. Scan detail satu IP + port           ║
  ║  4. Live monitor jaringan                ║
  ║  5. Tampilkan hasil scan terakhir        ║
  ║  6. Simpan hasil ke file                 ║
  ║  7. Keluar                               ║
  ╚══════════════════════════════════════════╝{R}""")

        try:
            choice = input(f"  {YLW}Pilih [1-7]: {R}").strip()
        except (EOFError, KeyboardInterrupt):
            break

        # ── 1. Scan jaringan ─────────────────────────────────────────────────
        if choice == "1":
            subnets = get_local_subnets()
            if not subnets:
                print(f"\n  {RED}[!]{R} Tidak ada interface jaringan terdeteksi.")
                cidr = input(f"  Masukkan CIDR manual (contoh 192.168.1.0/24): ").strip()
            else:
                print(f"\n  {GRN}[✓]{R} Interface aktif yang ditemukan:\n")
                for i, s in enumerate(subnets, 1):
                    print(f"    {i}. {s['iface']:12} {s['ip']:16} → {CYN}{s['cidr']}{R}")
                try:
                    idx = input(f"\n  {YLW}Pilih interface [{1}-{len(subnets)}] atau enter untuk pertama: {R}").strip()
                    idx = int(idx) - 1 if idx.isdigit() else 0
                    cidr = subnets[idx]["cidr"]
                except Exception:
                    cidr = subnets[0]["cidr"]

                alt = input(f"  {YLW}Gunakan {cidr}? [Y/n]: {R}").strip().lower()
                if alt == "n":
                    cidr = input("  Masukkan CIDR manual: ").strip()

            try:
                workers_raw = input(f"  {YLW}Worker paralel [default 100]: {R}").strip()
                workers = int(workers_raw) if workers_raw.isdigit() else 100
            except Exception:
                workers = 100

            print()
            last_devices, elapsed = scan_network(cidr, workers)
            print_devices(last_devices)
            print(f"  {BLU}[i]{R} Waktu scan: {elapsed:.2f} detik\n")

        # ── 2. Resolve hostname ───────────────────────────────────────────────
        elif choice == "2":
            subtool_resolve()

        # ── 3. Detail satu IP ────────────────────────────────────────────────
        elif choice == "3":
            subtool_detail()

        # ── 4. Live monitor ──────────────────────────────────────────────────
        elif choice == "4":
            subtool_monitor()

        # ── 5. Tampilkan hasil terakhir ──────────────────────────────────────
        elif choice == "5":
            if last_devices:
                print_devices(last_devices)
            else:
                print(f"\n  {YLW}[!]{R} Belum ada scan yang dilakukan.\n")

        # ── 6. Simpan ke file ────────────────────────────────────────────────
        elif choice == "6":
            if not last_devices:
                print(f"\n  {YLW}[!]{R} Belum ada data untuk disimpan.\n")
                continue
            fname = f"wifi_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                with open(fname, "w") as f:
                    f.write("No,IP,Hostname,MAC,Vendor,Latency_ms\n")
                    for i, d in enumerate(last_devices, 1):
                        f.write(f"{i},{d['ip']},{d['hostname']},{d['mac']},{d['vendor']},{d['latency']}\n")
                print(f"\n  {GRN}[✓]{R} Hasil disimpan ke: {BLD}{fname}{R}\n")
            except Exception as e:
                print(f"\n  {RED}[!]{R} Gagal menyimpan: {e}\n")

        # ── 7. Keluar ────────────────────────────────────────────────────────
        elif choice in ("7", "q", "quit"):
            print(f"\n  {CYN}[✓]{R} Keluar. Sampai jumpa!\n")
            sys.exit(0)

        else:
            print(f"\n  {RED}[!]{R} Pilihan tidak valid.\n")

# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Cek hak akses root untuk fitur penuh
    try:
        is_root = os.geteuid() == 0
    except AttributeError:
        is_root = False   # Windows

    if not is_root:
        print(f"\n  {YLW}[!]{R} Menjalankan tanpa sudo. "
              f"ARP scan dinonaktifkan, beberapa fitur mungkin terbatas.")
        print(f"      Rekomendasi: {BLD}sudo python3 {sys.argv[0]}{R}\n")

    main_menu()