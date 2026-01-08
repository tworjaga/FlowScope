# FlowScope - Installation Guide

## System Requirements

### Minimum Requirements
- **OS**: Windows 10/11, Linux (Ubuntu 20.04+, Debian 11+), macOS 11+
- **Python**: 3.10 or higher
- **RAM**: 4 GB
- **Disk Space**: 500 MB
- **Network**: Administrator/root privileges for packet capture

### Recommended Requirements
- **RAM**: 8 GB or more
- **CPU**: Multi-core processor
- **Disk Space**: 2 GB for sessions and logs

## Installation Steps

### 1. Install Python

#### Windows
Download and install Python from [python.org](https://www.python.org/downloads/)
- ✅ Make sure to check "Add Python to PATH" during installation

#### Linux (Ubuntu/Debian)
```bash
# Update package list
sudo apt update

# Install Python 3.10+ and development tools
sudo apt install python3.10 python3-pip python3-venv python3-dev

# Verify Python version
python3 --version
```

#### Linux (Fedora/RHEL/CentOS)
```bash
# Update package list
sudo dnf update

# Install Python 3.10+ and development tools
sudo dnf install python3.10 python3-pip python3-devel

# Verify Python version
python3 --version
```

#### Linux (Arch/Manjaro)
```bash
# Update package list
sudo pacman -Syu

# Install Python and development tools
sudo pacman -S python python-pip

# Verify Python version
python --version
```

#### macOS
```bash
brew install python@3.10
```

### 2. Install System Dependencies

#### Windows
- **Install [Npcap](https://npcap.com/)** (REQUIRED for packet capture)
- Download and run the Npcap installer
- ⚠️ **CRITICAL**: Enable "WinPcap API-compatible Mode" during installation
- ✅ Enable "Support raw 802.11 traffic" for WiFi analysis
- 🔄 Restart your computer after installation

#### Linux (Ubuntu/Debian)
```bash
# Install packet capture libraries
sudo apt install libpcap-dev tcpdump

# Install Python development headers
sudo apt install python3-dev build-essential

# Install Qt6 dependencies for PyQt6
sudo apt install qt6-base-dev libgl1-mesa-dev

# Install WiFi analysis tools
sudo apt install wireless-tools iw net-tools

# Install additional useful tools
sudo apt install wireshark-common  # For packet capture permissions
```

**Set up packet capture permissions (Ubuntu/Debian):**
```bash
# Add your user to wireshark group (allows non-root packet capture)
sudo usermod -a -G wireshark $USER

# Set capabilities for Python (alternative to running as root)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3.10)

# Log out and log back in for group changes to take effect
```

#### Linux (Fedora/RHEL/CentOS)
```bash
# Install packet capture libraries
sudo dnf install libpcap-devel tcpdump

# Install Python development headers
sudo dnf install python3-devel gcc gcc-c++ make

# Install Qt6 dependencies
sudo dnf install qt6-qtbase-devel mesa-libGL-devel

# Install WiFi analysis tools
sudo dnf install wireless-tools iw net-tools

# Install Wireshark for packet capture setup
sudo dnf install wireshark-cli
```

**Set up packet capture permissions (Fedora/RHEL):**
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Set capabilities for Python
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Reboot or log out/in for changes to take effect
```

#### Linux (Arch/Manjaro)
```bash
# Install packet capture libraries
sudo pacman -S libpcap tcpdump

# Install Python development tools
sudo pacman -S base-devel

# Install Qt6 dependencies
sudo pacman -S qt6-base

# Install WiFi analysis tools
sudo pacman -S wireless_tools iw net-tools

# Install Wireshark
sudo pacman -S wireshark-cli
```

**Set up packet capture permissions (Arch):**
```bash
# Add user to wireshark group
sudo usermod -a -G wireshark $USER

# Set capabilities for Python
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)

# Reboot for changes to take effect
```

#### macOS
```bash
brew install libpcap
```

### 3. Clone the Repository

```bash
# Clone from GitHub
git clone https://github.com/yourusername/flowscope.git
cd flowscope
```

Or download and extract the ZIP file from GitHub.

### 4. Create Virtual Environment (Recommended)

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate

# Linux/macOS:
source venv/bin/activate
```

### 5. Install Python Dependencies

```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install all requirements
pip install -r requirements.txt
```

**Dependencies installed:**
- `PyQt6>=6.4.0` - Modern GUI framework
- `scapy>=2.5.0` - Packet manipulation
- `psutil>=5.9.0` - System utilities
- `matplotlib>=3.7.0` - Graphs and charts
- `cryptography>=41.0.0` - TLS certificate parsing
- `netifaces>=0.11.0` - Network interface info

**Note**: If you encounter issues with scapy on Windows:
```bash
pip install scapy[complete]
```

### 6. Verify Installation

```bash
# Check Python version
python --version

# Check installed packages
pip list

# Test imports
python -c "from PyQt6.QtWidgets import QApplication; print('✅ PyQt6 OK')"
python -c "from scapy.all import sniff; print('✅ Scapy OK')"
python -c "from cryptography import x509; print('✅ Cryptography OK')"

# Run test capture
python test_capture.py
```

## Running FlowScope

### GUI Mode (Recommended)

#### Windows
```bash
# IMPORTANT: Run as Administrator (required for packet capture)
# Right-click Command Prompt -> "Run as Administrator"
cd path\to\flowscope
venv\Scripts\activate
python main.py
```

Or use the provided batch file:
```bash
start.bat
```

#### Linux

**Method 1: Using sudo (Recommended for testing)**
```bash
cd /path/to/flowscope
source venv/bin/activate
sudo -E python main.py
```

**Method 2: Using capabilities (Recommended for production)**
```bash
# Set capabilities on Python binary (one-time setup)
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)

# Run without sudo
cd /path/to/flowscope
source venv/bin/activate
python main.py
```

**Method 3: Using wireshark group (Most secure)**
```bash
# Add user to wireshark group (one-time setup)
sudo usermod -a -G wireshark $USER
# Log out and log back in

# Run without sudo
cd /path/to/flowscope
source venv/bin/activate
python main.py
```

**Create a launcher script (Optional):**
```bash
# Create run.sh
cat > run.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python main.py
EOF

# Make executable
chmod +x run.sh

# Run
./run.sh
```

#### macOS
```bash
cd /path/to/flowscope
source venv/bin/activate
sudo python main.py
```

### Headless Mode

Capture packets without GUI:

```bash
python main.py --headless --duration 60 --output capture.pcap
```

**Options:**
- `--headless`: Run without GUI
- `--duration SECONDS`: Capture duration
- `--output FILE`: Output PCAP file
- `--interface IFACE`: Network interface
- `--filter "FILTER"`: BPF filter expression

**Example:**
```bash
# Capture HTTP traffic for 5 minutes
python main.py --headless --duration 300 --filter "tcp port 80" --output http_capture.pcap
```

### API Mode

Start REST API server:

```bash
python main.py --api --port 8080
```

Access API at: `http://localhost:8080/api/`

## Configuration

### Edit Settings

Edit `config/settings.yaml` to customize:

```yaml
capture:
  default_interface: "auto"  # or specific interface name
  buffer_size: 65536
  max_packets: 100000

ui:
  theme: "dark"
  window_width: 1600
  window_height: 900
  update_interval: 100  # milliseconds

anomaly_detection:
  enabled: true
  dns_threshold: 100  # queries per minute
  port_scan_threshold: 20  # ports
  beaconing_threshold: 10  # connections
```

### Network Interfaces

**List available interfaces:**

```python
from scapy.all import get_if_list
print(get_if_list())
```

Or use system commands:
```bash
# Windows
ipconfig /all

# Linux
ip addr show
# or
ifconfig -a

# macOS
ifconfig
```

## Troubleshooting

### ❌ Issue: "Permission Denied" Error

**Solution**: Run with administrator/root privileges

**Windows:**
- Right-click Command Prompt → "Run as Administrator"
- Or right-click `start.bat` → "Run as Administrator"

**Linux/macOS:**
```bash
sudo python main.py
```

### ❌ Issue: "No module named 'scapy'"

**Solution**: Install scapy
```bash
pip install scapy
```

### ❌ Issue: "Could not find Qt platform plugin"

**Solution**: Reinstall PyQt6
```bash
pip uninstall PyQt6 PyQt6-Qt6 PyQt6-sip
pip install PyQt6
```

### ❌ Issue: "0 packets captured" on Windows

**Solution**: 
1. ✅ Install Npcap from https://npcap.com/
2. ✅ Enable "WinPcap API-compatible Mode" during installation
3. ✅ Enable "Support raw 802.11 traffic" for WiFi
4. 🔄 Restart computer
5. ✅ Run as Administrator
6. ✅ Select correct network interface (WiFi/Ethernet)
7. 📖 Read `NPCAP_SETUP_GUIDE.md` for detailed instructions

### ❌ Issue: NoneType Errors (FIXED in v2.0)

**Status**: ✅ All NoneType errors have been fixed in:
- `packet_capture.py` - TCP flag parsing
- `filter_engine.py` - Filter operations
- `flow_engine.py` - Flow tracking
- `anomaly_detector.py` - Anomaly detection

### ❌ Issue: "Task was destroyed but it is pending"

**Status**: ✅ Fixed in v2.0 with proper asyncio task management

### ❌ Issue: TLS Handshakes Not Captured

**Platform Note**: ⚠️ TLS handshake capturing works best on **Linux** systems. Windows may have limitations with raw packet capture.

**Solutions:**
1. ✅ Ensure Npcap is installed correctly
2. ✅ Run as Administrator
3. ✅ Check that raw packet storage is enabled
4. ✅ Verify TLS traffic is present (port 443)

### ❌ Issue: High CPU Usage

**Solution**:
1. Reduce update interval in `config/settings.yaml`:
   ```yaml
   ui:
     update_interval: 200  # Increase from 100
   ```
2. Apply filters to reduce packet count
3. Increase buffer size
4. Reduce max packets in memory

### ❌ Issue: Application Crashes on Startup

**Solution**:
1. Check Python version: `python --version` (must be 3.10+)
2. Verify all dependencies: `pip list`
3. Check logs: `logs/analyzer.log`
4. Delete database: `sessions/analyzer.db` and restart
5. Reinstall dependencies: `pip install -r requirements.txt --force-reinstall`

## Performance Optimization

### For High-Traffic Networks

Edit `config/settings.yaml`:

```yaml
performance:
  max_packets_memory: 50000  # Reduce from 100000
  update_interval_ms: 200    # Increase from 100
  async_workers: 8           # Increase workers
  buffer_size: 131072        # Increase buffer
```

### For Low-Memory Systems

```yaml
performance:
  max_packets_memory: 10000
  update_interval_ms: 500
  async_workers: 2
```

### For WiFi Analysis

```yaml
wifi:
  scan_interval: 5  # seconds
  signal_history_size: 100
  enable_vendor_lookup: true
```

## Updating FlowScope

```bash
cd flowscope

# Pull latest changes (if using git)
git pull

# Update dependencies
pip install -r requirements.txt --upgrade

# Check for breaking changes
cat CHANGELOG.md  # if available
```

## Uninstallation

```bash
# Deactivate virtual environment
deactivate

# Remove virtual environment
rm -rf venv  # Linux/macOS
rmdir /s venv  # Windows

# Remove application data (optional)
rm -rf sessions/
rm -rf logs/
rm -rf __pycache__/
```

## Getting Help

- 📖 **Documentation**: Check `README.md` for features
- 🐛 **Known Issues**: Review `TODO.md`
- 📝 **Logs**: Check `logs/analyzer.log` for errors
- 🔧 **Npcap Setup**: Read `NPCAP_SETUP_GUIDE.md` (Windows)
- 🚀 **Quick Start**: See `БЫСТРЫЙ_СТАРТ.md` (Russian)
- 💬 **GitHub Issues**: Open an issue on GitHub

## Quick Start After Installation

1. **Start FlowScope**: 
   ```bash
   python main.py  # As Administrator/sudo
   ```

2. **Select Network Interface**: 
   - Auto-detected or choose from dropdown
   - WiFi for wireless analysis
   - Ethernet for wired networks

3. **Start Capture**: 
   - Click "▶ Start" button
   - Watch packets appear in real-time

4. **Explore Features**:
   - 📊 **Statistics Tab**: View traffic metrics
   - 📈 **Graphs Tab**: Real-time visualizations
   - 🔍 **Filters Tab**: Focus on specific traffic
   - 📡 **WiFi Analysis Tab**: Scan networks
   - 🔒 **TLS Handshakes Tab**: View encrypted connections
   - ⚠️ **Anomalies Dock**: Security alerts

5. **Apply Filters**:
   - Quick filters: HTTP/HTTPS, DNS
   - Custom filters: IP, port, protocol
   - Save filter presets

6. **Export Data**:
   - File → Export → CSV/PCAP/HTML
   - Save session for later analysis

## Advanced Configuration

### Custom Plugins

Place plugins in `plugins/` directory:

```python
# plugins/my_plugin.py
class MyPlugin:
    def __init__(self):
        self.name = "My Custom Plugin"
        
    def process_packet(self, packet_info):
        # Your custom packet processing logic
        if packet_info.get('protocol') == 'HTTP':
            print(f"HTTP packet: {packet_info['src_ip']}")
```

### Database Configuration

For PostgreSQL instead of SQLite:

```yaml
database:
  type: "postgresql"
  host: "localhost"
  port: 5432
  database: "flowscope"
  username: "user"
  password: "password"
```

### API Authentication

Enable API authentication in `config/settings.yaml`:

```yaml
api:
  enabled: true
  auth_required: true
  api_key: "your-secret-key-here"
  cors_origins: ["http://localhost:3000"]
```

### Anomaly Detection Tuning

Customize anomaly detection thresholds:

```yaml
anomaly_detection:
  dns_threshold: 100        # DNS queries per minute
  port_scan_threshold: 20   # Ports scanned
  beaconing_threshold: 10   # Regular connections
  rate_limit_pps: 1000      # Packets per second
  rate_limit_bps: 10485760  # Bytes per second (10 MB/s)
```

## Security Considerations

⚠️ **Important Security Notes**:

1. **Minimum Privileges**: Only use admin/root when capturing packets
2. **Secure API**: Enable authentication if exposing API to network
3. **Protect Sessions**: Session files may contain sensitive network data
4. **Network Isolation**: Consider running on isolated network for testing
5. **Data Retention**: Configure auto-cleanup for old sessions
6. **Encryption**: Sessions are stored unencrypted by default
7. **Access Control**: Restrict access to FlowScope installation directory

## Platform-Specific Notes

### Windows
- ✅ Requires Npcap with WinPcap compatibility
- ✅ Must run as Administrator
- ⚠️ TLS capture may have limitations
- ✅ WiFi analysis requires "raw 802.11 traffic" support

### Linux
- ✅ Best platform for TLS handshake capture
- ✅ Requires sudo for packet capture
- ✅ Full WiFi analysis support
- ✅ Better performance for high-traffic networks

### macOS
- ✅ Native libpcap support
- ✅ Requires sudo for packet capture
- ⚠️ WiFi analysis may be limited
- ✅ Good overall compatibility

## What's New in Version 2.0

### ✅ Fixed Issues
- **NoneType Errors**: All TCP flag parsing errors resolved
- **Asyncio Warnings**: Proper task cancellation implemented
- **TLS Capture**: Enhanced with proper Scapy layer access
- **Memory Leaks**: Improved buffer management

### ✨ New Features
- **Enhanced Anomaly Detection**: 10,000 anomaly buffer, callback system
- **Anomaly Panel**: Professional UI with filtering and export
- **Packet Details Panel**: 3-tab viewer (Summary, Hex Dump, Raw Data)
- **TLS Handshake Panel**: Complete handshake tracking with platform note
- **Top IPs/Ports**: Statistics panel enhancements

### 🔧 Improvements
- Better error handling across all modules
- Improved performance for high-traffic networks
- Enhanced WiFi analysis capabilities
- More detailed logging and diagnostics

## Support & Community

- 📧 **Email**: support@flowscope.dev (example)
- 💬 **GitHub**: https://github.com/yourusername/flowscope
- 📖 **Documentation**: See README.md and other guides
- 🐛 **Bug Reports**: Open GitHub issue
- 💡 **Feature Requests**: Open GitHub issue

## License

FlowScope is licensed under the MIT License. See `LICENSE.txt` for details.

---

**Happy Network Analysis! 🔍📊🔒**
