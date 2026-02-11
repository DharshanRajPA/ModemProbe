# Quick Start Guide - ModemProbe

## Prerequisites (Linux Only)

This project requires Linux with the following packages:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential cmake libpcap-dev libjsoncpp-dev

# Fedora/RHEL
sudo dnf install gcc-c++ cmake libpcap-devel jsoncpp-devel
```

## Build Steps

1. **Navigate to project directory:**
```bash
cd ModemProbe
```

2. **Create and enter build directory:**
```bash
mkdir build
cd build
```

3. **Configure with CMake:**
```bash
cmake ..
```

4. **Compile:**
```bash
make
```

5. **Run (requires sudo for packet capture):**
```bash
sudo ./modemprobe
```

Or specify an interface:
```bash
sudo ./modemprobe eth0
```

## What to Expect

- The program will start capturing packets
- Periodic statistics are printed every 10 seconds
- Press `Ctrl+C` to stop and generate a JSON report
- Report is saved as `modemprobe_report.json` in the current directory

## Troubleshooting

**"libpcap not found"**
```bash
sudo apt-get install libpcap-dev
```

**"jsoncpp not found"**
```bash
sudo apt-get install libjsoncpp-dev
```

**"Permission denied"**
Packet capture requires root privileges - use `sudo`

**"No such device"**
List interfaces with: `ip link show` or `ifconfig`, then use the correct interface name

