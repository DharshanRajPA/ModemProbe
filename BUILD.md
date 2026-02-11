# Building and Running ModemProbe

## Prerequisites

### Linux (Ubuntu/Debian)
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libpcap-dev libjsoncpp-dev
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install gcc-c++ cmake libpcap-devel jsoncpp-devel
```

## Building

1. **Create build directory:**
```bash
mkdir build
cd build
```

2. **Configure with CMake:**
```bash
cmake ..
```

3. **Build the project:**
```bash
make
```

The executable will be created as `modemprobe` in the build directory.

## Running

### Basic Usage

**Capture packets on default interface (loopback):**
```bash
sudo ./modemprobe
```

**Capture packets on a specific interface:**
```bash
sudo ./modemprobe eth0
```

**List available network interfaces:**
```bash
# Run without arguments to see available devices if default fails
sudo ./modemprobe
```

### Requirements

- **Root/sudo privileges** are required to capture packets from network interfaces
- The program will generate a JSON report (`modemprobe_report.json`) when you stop it with Ctrl+C

### Example Output

```
ModemProbe - Baseband Protocol Analyzer
========================================

Capturing on interface: eth0
Press Ctrl+C to stop and generate report

--- Periodic Report ---
Packets/sec: 1234.56
Total packets: 12345
TCP: 8000, UDP: 4000
HTTP: 500, DNS: 200
RTP streams: 3
Anomalies: 0
```

## Troubleshooting

### "libpcap not found"
Install libpcap development package:
```bash
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo dnf install libpcap-devel    # Fedora/RHEL
```

### "jsoncpp not found"
Install jsoncpp development package:
```bash
sudo apt-get install libjsoncpp-dev  # Ubuntu/Debian
sudo dnf install jsoncpp-devel       # Fedora/RHEL
```

### "Permission denied" when running
Packet capture requires root privileges. Use `sudo`:
```bash
sudo ./modemprobe
```

### "No such device" error
List available network interfaces:
```bash
ip link show
# or
ifconfig
```
Then specify the correct interface name.

