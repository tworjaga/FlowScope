# FlowScope 🔍

Professional-grade network traffic analyzer with advanced protocol analysis, real-time visualization, and anomaly detection.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com)

## Features

### TLS/HTTPS Analysis (Enhanced)
- **Multi-Port TLS Detection** - Ports 443, 8443, 4433, 10443
- **Complete TLS Handshake Capture** - All handshake stages tracked
- **Full X.509 Certificate Parsing** - Subject, Issuer, Validity, Serial Number
- **Enhanced JA3 Fingerprinting** - Complete 5-component fingerprint
- **Advanced Extension Parsing** - SNI, ALPN, Supported Groups, Signature Algorithms
- **TLS Version Detection** - TLS 1.0/1.1/1.2/1.3
- **Cipher Suite Analysis** - All cipher suites captured and analyzed
- **Certificate Chain Validation** - Full certificate details
- **Session Tracking** - Session ID and ticket monitoring

### WiFi Network Analysis (Enhanced)
- **Cross-Platform Scanning** - Windows, Linux, macOS support
- **MAC Vendor Lookup** - Identifies 30+ device manufacturers
- **Rogue AP Detection** - Detects duplicate SSIDs with different BSSIDs
- **Enhanced Security Analysis** - Color-coded warnings ( Critical,  Warning,  Info)
- **WPA3 Detection** - Latest security standard support
- **Interference Analysis** - Channel overlap and interference scoring
- **Smart Channel Recommendations** - Best channels for 2.4GHz and 5GHz
- **Suspicious SSID Detection** - Identifies potentially malicious networks
- **Hidden SSID Detection** - Flags security through obscurity
- **Signal Strength History** - Track signal quality over time
- **Network History Tracking** - Monitor network appearances
- **Deauth Attack Detection** - Identifies potential attacks
- **Comprehensive Reports** - Detailed WiFi environment analysis

### Protocol Analysis
- TCP/UDP with detailed flag analysis (None-safe)
- ICMP (ping, unreachable messages)
- ARP (network discovery)
- DHCP (IP assignment tracking)
- DNS with query tracking
- HTTP/HTTPS traffic analysis
- NTP (time synchronization)
- mDNS/SSDP (device discovery)
- QUIC (detection and analysis)

### Advanced Filtering
- IP range filtering
- Port filtering
- Protocol filtering
- Direction filtering (in/out)
- Time-based filtering
- Combined filters (AND/OR)
- Saved filter presets

### Statistics & Metrics
- PPS (packets per second)
- BPS (bytes per second)
- Top IPs by traffic
- Top domains (DNS/SNI)
- Top ports
- Traffic histograms
- Spike detection
- Idle/active period analysis

### Real-time Visualization
- Live traffic graphs
- Protocol distribution charts
- DNS/HTTP/TLS activity graphs
- Activity heatmaps
- Source→Destination flow diagrams
- Timeline view
- Packet mini-maps

### WiFi Network Analysis
- WiFi network scanning (Windows/Linux/macOS)
- Signal strength monitoring
- Channel congestion analysis
- Security vulnerability detection
- Best channel recommendations
- Connected network details
- Network quality assessment
- Auto-refresh capability
- Comprehensive WiFi reports

### Anomaly Detection (Enhanced)
- **Excessive DNS Queries** - Detects DNS tunneling attempts
- **Port Scanning Detection** - Identifies reconnaissance activity
- **Suspicious Port Usage** - Flags dangerous ports (SSH, RDP, SMB, etc.)
- **Unusual SNI Patterns** - Detects Tor, suspicious domains
- **Beaconing Detection** - Identifies C2 communication patterns
- **Rate-Limit Violations** - PPS/BPS threshold monitoring
- **VPN/Proxy Detection** - Identifies encrypted tunnel usage
- **DNS over HTTPS Detection** - Tracks DoH usage
- **DDoS Detection** - Connection attempt monitoring

### Export & Reporting
- CSV export
- PCAP export (Wireshark compatible)
- HTML reports with charts
- Auto-save sessions
- Session comparison
- Syslog export

### UI/UX Features
- Dark theme (strict & pleasant)
- Context menus
- Detailed packet inspection
- Color profiles
- Sortable/pinnable columns
- Dockable panels
- Hotkeys support
- Zoom controls

### Advanced Features
- Plugin system
- Configuration profiles
- REST API
- Headless mode
- Role-based access (viewer/analyst)
- Capture timers
- Auto-start sessions
- Domain blacklist/whitelist
- VPN/Proxy detection
- DNS over HTTPS detection

## 🛠️ Installation

### Prerequisites
- Python 3.10 or higher
- Administrator/root privileges (for packet capture)
- **Npcap** (Windows) - [Download here](https://npcap.com/)
  - ⚠️ **IMPORTANT**: Install with "WinPcap API-compatible Mode" enabled
  - Enable "Support raw 802.11 traffic" for WiFi analysis

### Quick Install

```bash
# Clone the repository
git clone https://github.com/tworjaga/flowscope.git
cd flowscope

# Install dependencies
pip install -r requirements.txt

# Run the analyzer (requires admin/root privileges)
python main.py
```

### Dependencies
```
PyQt6>=6.4.0
scapy>=2.5.0
psutil>=5.9.0
matplotlib>=3.7.0
cryptography>=41.0.0  # For enhanced TLS certificate parsing
netifaces>=0.11.0     # For WiFi analysis
```

## Quick Start

### GUI Mode (Recommended)
```bash
# Windows (Run as Administrator)
python main.py

# Linux/macOS (Run with sudo)
sudo python main.py
```

### Headless Mode
```bash
# Capture for 1 hour and save to file
python main.py --headless --duration 3600 --output capture.pcap

# Capture with specific interface
python main.py --headless --interface eth0 --output capture.pcap
```

### API Mode
```bash
# Start REST API server
python main.py --api --port 8080

# Access API at http://localhost:8080/api/
```

### Test Capture
```bash
# Test if packet capture is working
python test_capture.py
```

## Hotkeys

- `Ctrl+S` - Save session
- `Ctrl+O` - Open session
- `Ctrl+E` - Export to CSV
- `Ctrl+F` - Open filter dialog
- `Ctrl+P` - Pause/Resume capture
- `Ctrl+R` - Reset statistics
- `F5` - Refresh view
- `F11` - Toggle fullscreen
- `Space` - Pause/Resume

## Configuration

Edit `config/settings.yaml` to customize:
- Capture interface
- Buffer sizes
- Update intervals
- Theme colors
- Plugin settings

## Architecture

```
flowscope/
├── backend/          # Core packet capture & analysis
├── frontend/         # PyQt6 GUI
├── config/           # Configuration files
├── plugins/          # Plugin system
├── sessions/         # Saved capture sessions
└── logs/            # Application logs
```

## Requirements

- Python 3.10+
- **Npcap** (Windows) - https://npcap.com/
  - ОБЯЗАТЕЛЬНО с WinPcap API-compatible Mode
  - Support raw 802.11 traffic
- Administrator/root privileges (for packet capture)
- Windows/Linux/macOS

## Documentation

- **[Installation Guide](INSTALL.md)** - Detailed installation instructions
- **[Npcap Setup Guide](NPCAP_SETUP_GUIDE.md)** - Windows packet capture setup
- **[Quick Start Guide](БЫСТРЫЙ_СТАРТ.md)** - Get started in 5 minutes
- **[Project Summary](PROJECT_SUMMARY.md)** - Complete feature overview
- **[Testing Results](TESTING_RESULTS.md)** - Validation and test results

## Troubleshooting

### "0 packets captured"
1. **Read `NPCAP_SETUP_GUIDE.md`** for Windows setup
2. **Run `test_capture.py`** for diagnostics
3. **Install Npcap correctly** with WinPcap compatibility mode
4. **Select active network interface** (WiFi/Ethernet)
5. **Run as Administrator/root**

### "Permission denied"
- **Windows**: Run Command Prompt as Administrator
- **Linux/macOS**: Use `sudo python main.py`

### "No such device exists"
- Check interface name in `test_capture.py`
- Reinstall Npcap (Windows)
- Check `ifconfig` or `ip addr` (Linux)

### NoneType Errors (Fixed)
All NoneType errors in TCP flag parsing have been resolved in:
- `packet_capture.py`
- `filter_engine.py`
- `flow_engine.py`
- `anomaly_detector.py`

### Asyncio Task Warnings (Fixed)
Proper task cancellation implemented for clean shutdown.

## Use Cases

- **Network Security Analysis** - Detect intrusions and anomalies
- **WiFi Site Surveys** - Optimize wireless network deployment
- **Protocol Debugging** - Analyze application-level protocols
- **Performance Monitoring** - Track network bandwidth and latency
- **Compliance Auditing** - Monitor network security policies
- **Penetration Testing** - Identify vulnerabilities
- **IoT Device Analysis** - Monitor smart device communications
- **TLS/SSL Inspection** - Analyze encrypted traffic metadata

## 🔧 Recent Updates

### Version 2.0 (Latest)
- **Enhanced TLS Analysis** - Complete handshake capture with JA3 fingerprinting
- **Powerful WiFi Tools** - Rogue AP detection, vendor lookup, interference analysis
- **Fixed All NoneType Errors** - Robust TCP flag parsing across all modules
- **Asyncio Task Management** - Proper task cancellation and cleanup
- **Enhanced Security Detection** - WPA3 support, suspicious SSID detection
- **Better Certificate Parsing** - Full X.509 details with cryptography library
- **Improved UI** - Packet details panel, TLS handshake panel integration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE.txt) file for details.

## Author

Created for professional network analysis and security research.

## Acknowledgments

- Scapy - Powerful packet manipulation library
- PyQt6 - Modern GUI framework
- Npcap - Windows packet capture driver
- cryptography - TLS certificate parsing

## Star History

If you find this project useful, please consider giving it a star!

---

**Note**: This tool is for educational and professional network analysis purposes only. Always ensure you have proper authorization before analyzing network traffic.




