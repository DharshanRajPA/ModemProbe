# ModemProbe – QUICKSTART

Exact commands to build and run this project from scratch on a fresh Ubuntu/Debian Linux machine.

---

## Step 1: Install dependencies

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake g++ libpcap-dev libjsoncpp-dev
```

Verify they are installed:

```bash
cmake --version        # must be >= 3.16
g++ --version          # must support C++17
pkg-config --modversion libpcap    # should print e.g. 1.10.1
pkg-config --modversion jsoncpp    # should print e.g. 1.9.5
```

---

## Step 2: Clone the repo (if you haven't already)

```bash
git clone https://github.com/YOUR_USERNAME/ModemProbe.git
cd ModemProbe
```

Or if you already have it:

```bash
cd /path/to/ModemProbe
```

---

## Step 3: Build

```bash
cmake -S . -B build
cmake --build build
```

Expected output ends with:

```
[9/9] Linking CXX executable modemprobe
```

The binary is at `./build/modemprobe`.

---

## Step 4: Run – Demo mode (NO network, NO sudo, works immediately)

```bash
./build/modemprobe --demo
```

This generates synthetic WiFi 802.11 beacons + LTE PDSCH/PUSCH frames, processes
them through the full pipeline, and writes `report.json`. No root, no network needed.

Expected output:

```
Ring buffer: 1024 slots, 2112.0 KB
========================================
 ModemProbe – Simulation Demo
========================================

--- WiFi 802.11 Beacon Simulation ---
  Beacon 0: SSID="ModemProbe_AP0" CH=1
  Beacon 1: SSID="ModemProbe_AP1" CH=2
  ...

--- LTE PDSCH (Downlink) Simulation ---
  SF0: MCS=10 PRB=50 RNTI=0x1234
  SF1: MCS=11 PRB=50 RNTI=0x1234
  ...

--- LTE PUSCH (Uplink) Simulation ---
  Generated 10 PUSCH subframes (RNTI=0x5678)

--- ModemProbe stats (0.0s) ---
Packets: 28 | Bytes: ... | pps: ... | avg_parse: ... us
Protocols:  Ethernet=28  IPv4=28  UDP=28  WiFi_Beacon=8  LTE_PDSCH=10  LTE_PUSCH=10
...

JSON report: report.json
```

---

## Step 5: Run – Offline pcap file (NO sudo)

If you have a `.pcap` file:

```bash
./build/modemprobe --pcap sample.pcap
```

Or with a custom report output path:

```bash
./build/modemprobe --pcap sample.pcap --report my_report.json
```

To also inject WiFi/LTE simulation alongside real packets:

```bash
./build/modemprobe --pcap sample.pcap --inject-wifi --inject-lte
```

If you don't have a pcap file, create one quickly:

```bash
# Capture 100 packets on loopback (needs sudo)
sudo tcpdump -i lo -c 100 -w sample.pcap

# Then process it without sudo
./build/modemprobe --pcap sample.pcap
```

---

## Step 6: Run – Live capture (needs sudo)

```bash
# Capture on loopback for 5 seconds
sudo ./build/modemprobe --iface lo --seconds 5

# Capture on eth0 for 10 seconds
sudo ./build/modemprobe --iface eth0 --seconds 10

# Capture on wlan0 with WiFi/LTE sim injection
sudo ./build/modemprobe --iface wlan0 --seconds 10 --inject-wifi --inject-lte

# Capture with custom report path
sudo ./build/modemprobe --iface lo --seconds 5 --report live_report.json
```

To generate traffic during live capture (open another terminal):

```bash
# Generate HTTP traffic on loopback
curl http://localhost/ 2>/dev/null
ping -c 5 127.0.0.1
```

---

## Step 7: Run – Live capture with raw sockets (optional, needs recompile)

```bash
# Rebuild with raw socket support
cmake -S . -B build -DMODEMPROBE_ENABLE_RAW_SOCKET=ON
cmake --build build

# Run with raw socket backend
sudo ./build/modemprobe --iface eth0 --seconds 10 --backend raw
```

---

## Step 8: View the JSON report

```bash
cat report.json
```

Or pretty-print:

```bash
python3 -m json.tool report.json
```

The report contains:
- `protocol_counts` – Ethernet, IPv4, TCP, UDP, HTTP, DNS, RTP, SIP, H264_NAL, WiFi_Beacon, LTE_PDSCH, LTE_PUSCH
- `anomalies` – sequence gaps, malformed headers, UDP length mismatches
- `performance` – packets_total, elapsed_seconds, pps, avg_parse_us
- `rtp_streams` – per-SSRC: received, lost, duplicates, out-of-order, H.264 detection

---

## All CLI options

```bash
./build/modemprobe --help
```

```
ModemProbe – Baseband Protocol Analyzer & Packet Processor

Usage:
  modemprobe --pcap <file.pcap> [options]
  modemprobe --iface <eth0|lo|wlan0> [--seconds <N>] [options]
  modemprobe --demo [options]

Capture options:
  --pcap <file>          Read packets from a .pcap file (no sudo needed)
  --iface <name>         Live capture on interface (needs sudo)
  --seconds <N>          Duration for live capture (default: 10)
  --backend <pcap|raw>   Capture backend: pcap (default) or raw (AF_PACKET)

Simulation options:
  --demo                 Run WiFi/LTE simulation demo (no network needed)
  --inject-wifi          Also inject WiFi 802.11 beacons during capture
  --inject-lte           Also inject LTE PDSCH/PUSCH frames during capture

Pipeline options:
  --pipeline <full|minimal>  Processing pipeline (default: full)
  --no-ring-buffer       Disable ring buffer (direct processing)

Output:
  --report <file>        JSON report path (default: report.json)
  --list-devices         List available interfaces and exit
  -h, --help             Show this help
```

---

## Quick one-liner demo (copy-paste this entire block)

```bash
sudo apt-get update && sudo apt-get install -y build-essential cmake g++ libpcap-dev libjsoncpp-dev && cmake -S . -B build && cmake --build build && ./build/modemprobe --demo && echo "=== Report ===" && python3 -m json.tool report.json
```

---

## File structure (what you're building)

```
ModemProbe/
├── CMakeLists.txt           # Build config (9 source files, libpcap + jsoncpp)
├── README.md                # Full documentation
├── QUICKSTART.md            # This file
└── src/
    ├── main.cpp             # Entry point: arg parsing, 4 run modes, stats, report
    ├── capture_pcap.cpp/h   # libpcap wrapper (live non-blocking + offline)
    ├── raw_socket.cpp/h     # AF_PACKET raw socket (Linux, compile flag)
    ├── ring_buffer.h        # Lock-free SPSC ring buffer (header-only, 1024 slots)
    ├── pipeline.h           # Configurable pipeline config (header-only)
    ├── parse.cpp/h          # Ethernet → IPv4 → TCP/UDP dissector
    ├── fingerprint.cpp/h    # HTTP/DNS/RTP/SIP detection + H.264 NAL codes
    ├── rtp_stream.cpp/h     # Per-SSRC RTP tracker (wrap, dedup, loss, OOO)
    ├── anomaly.cpp/h        # Anomaly detector (seq gaps, malformed headers)
    ├── wireless_sim.cpp/h   # WiFi beacon + LTE PDSCH/PUSCH simulator
    └── report_json.cpp/h    # JSON report writer (jsoncpp)
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `cmake` not found | `sudo apt install cmake` |
| `pkg-config` not found | `sudo apt install pkg-config` |
| `libpcap not found` | `sudo apt install libpcap-dev` |
| `jsoncpp not found` | `sudo apt install libjsoncpp-dev` |
| `Permission denied` on live capture | Use `sudo` |
| `raw socket support not compiled` | Rebuild with `-DMODEMPROBE_ENABLE_RAW_SOCKET=ON` |
| `No devices found` | Run with `sudo` |
