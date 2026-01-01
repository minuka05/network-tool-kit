# Network Analyzer 🛡️

A comprehensive, educational network analysis tool built with Python and Tkinter. This application provides a suite of tools for network administrators, cybersecurity students, and enthusiasts to analyze network health, discover devices, and audit security.

## ✨ Features

### 1. 🌐 Host Information
- **Reachability Check**: ICMP and TCP ping to check if a host is alive.
- **DNS Resolution**: Resolves hostnames to IPs and vice versa.
- **GeoIP Lookup**: Displays country, ISP, and location data for public IPs.
- **IP Intelligence**: Detects private, loopback, and multicast addresses.

### 2. 🔍 Port Scanner
- **Multi-threaded Scanning**: Fast scanning with adjustable thread counts.
- **Scan Profiles**: Quick Scan, Normal, Full Scan, Stealth Scan.
- **Scan Types**:
  - TCP Connect (Standard)
  - SYN Scan (Stealth - requires Npcap/Root)
  - UDP Scan
  - FIN / NULL / XMAS Scans
- **Service Detection**: Identifies running services on open ports.
- **Export**: Save results to HTML, JSON, CSV, or TXT.

### 3. 🛣️ Trace Route (MTR Style)
- **Visual Tracing**: Real-time visualization of network hops.
- **Statistics**: Packet loss, latency (min/avg/max), and jitter for each hop.
- **Geo-location**: Identifies the location of intermediate hops where possible.

### 4. ⭐ Network Discovery
- **LAN Scanning**: Discover all devices on your local network.
- **Methods**: ARP Scan (Layer 2 - Fast/Accurate) and Ping Sweep (Layer 3).
- **Device Details**: IP address, MAC address, Hostname, and Vendor detection (OUI lookup).
- **Interface Detection**: Automatically detects active network interfaces (WiFi/Ethernet) and subnets.

## 🚀 Installation

### Prerequisites
- **Python 3.8+**
- **Npcap** (Windows only): Required for ARP scanning and SYN/Stealth scans.
  - Download from [npcap.com](https://npcap.com/#download).
  - **Important**: Check "Install Npcap in WinPcap API-compatible Mode" during installation.

### Setup
1. **Clone the repository**
   ```bash
   git clone https://github.com/minuka05/network-tool-kit.git
   cd network-tool-kit
   ```

2. **Install Dependencies**
   The tool relies mostly on the Python standard library, but `scapy` is highly recommended for advanced features.
   ```bash
   pip install scapy
   ```

3. **Run the Application**
   ```bash
   python main.py
   ```

## 📂 Project Structure

- **`main.py`**: The main entry point of the application. Contains the GUI implementation using Tkinter.
- **`host_discovery.py`**: Handles network discovery features including ARP scanning, Ping sweeps, and DNS resolution.
- **`scanner_engine.py`**: Core logic for port scanning (TCP Connect, SYN, UDP) and service detection.
- **`utils.py`**: Helper functions for input validation, data formatting, and common utilities.
- **`reporting.py`**: Manages the export of scan results to various formats (HTML, JSON, CSV).
- **`config.py`**: Configuration settings and constants used throughout the application.
- **`requirements.txt`**: List of Python dependencies required to run the tool.

## ⚠️ Legal Disclaimer

**Usage of this tool for attacking targets without prior mutual consent is illegal.** It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

This project is intended for **educational purposes only**.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.
## 🙏 Acknowledgments

- Inspired by Nmap and other security scanning tools
- Built for cybersecurity education community
- Thanks to the open-source security community

---

## ⚖️ Responsible Disclosure

If you discover security vulnerabilities in networks using this tool during authorized testing:

1. Do NOT exploit the vulnerability
2. Document findings professionally
3. Report to system owner immediately
4. Allow time for remediation before disclosure
5. Follow responsible disclosure guidelines

---

**Remember: With great power comes great responsibility. Use this tool ethically and legally!**

For questions or concerns: [Create an issue on GitHub]

---

*Last updated: January 2026*
