# ModemProbe

**Baseband Protocol Analyzer & Packet Processor**
C++ · Linux · Socket Programming · libpcap

Real-time and offline packet capture using libpcap and raw sockets (AF_PACKET),
protocol dissection (Ethernet → IPv4 → TCP/UDP), application-layer fingerprinting
(HTTP, DNS, RTP, SIP), H.264 NAL start-code detection, RTP stream loss/gap tracking,
WiFi 802.11 beacon and LTE PDSCH/PUSCH frame simulation, anomaly detection,
lock-free ring buffer architecture, and JSON reporting.

---

## Features

- **Real-time capture** on any Linux interface using libpcap (non-blocking) or raw sockets (AF_PACKET)
- **Offline mode** — process `.pcap` files without root
- **Protocol dissection** — Ethernet → IPv4 → TCP/UDP with ports, seq/ack, lengths
- **Application fingerprinting** — HTTP (methods incl. DELETE), DNS (port 53), RTP (v2 + port heuristics), SIP (all keywords length-guarded)
- **Multimedia** — detect H.264 NAL start codes (`00 00 01` / `00 00 00 01`) in RTP payloads
- **RTP stream tracking** — per-SSRC sequence tracking with correct 16-bit wrap-around, duplicate/out-of-order detection, and loss estimation via 1024-entry bitmap replay window
- **WiFi 802.11 beacon simulation** — generate synthetic beacon frames with SSID, BSSID, channel, beacon interval
- **LTE PDSCH/PUSCH simulation** — generate synthetic downlink/uplink frame patterns with RNTI, subframe, PRB, MCS
- **Lock-free SPSC ring buffer** — pre-allocated fixed-size packet pool (1024 slots, ~2 MB), `std::atomic` head/tail, zero heap allocation after init
- **Configurable processing pipeline** — select `full` or `minimal` at runtime; toggle individual protocol layers
- **Anomaly detection** — malformed headers, UDP length mismatch, TCP sequence gaps (32-bit wrap-aware)
- **Periodic console stats** every 2 seconds
- **Final JSON report** — protocol counts, anomaly summary, performance metrics (pps, avg parse time), RTP stream details

---

## Prerequisites

```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake g++ libpcap-dev libjsoncpp-dev

# Fedora / RHEL
sudo dnf install cmake gcc-c++ libpcap-devel jsoncpp-devel
```

---

## Build

```bash
# Standard build (libpcap backend, raw socket stub)
cmake -S . -B build
cmake --build build

# With raw socket support enabled (Linux only, requires sudo to run)
cmake -S . -B build -DMODEMPROBE_ENABLE_RAW_SOCKET=ON
cmake --build build
```

The resulting binary is `build/modemprobe`.

---

## Run

### 1. Live capture with libpcap (requires sudo)

```bash
# Capture on loopback for 5 seconds
sudo ./build/modemprobe --iface lo --seconds 5

# Capture on eth0 for 30 seconds, custom report path
sudo ./build/modemprobe --iface eth0 --seconds 30 --report eth0_report.json

# Capture on Wi-Fi
sudo ./build/modemprobe --iface wlan0 --seconds 10
```

### 2. Live capture with raw sockets (requires sudo + compile flag)

```bash
sudo ./build/modemprobe --iface eth0 --seconds 10 --backend raw
```

### 3. Offline pcap processing (no sudo)

```bash
./build/modemprobe --pcap sample.pcap
./build/modemprobe --pcap sample.pcap --report my_report.json
```

### 4. With WiFi/LTE simulation injection

```bash
sudo ./build/modemprobe --iface lo --seconds 5 --inject-wifi --inject-lte
./build/modemprobe --pcap sample.pcap --inject-wifi --inject-lte
```

### 5. Pipeline modes

```bash
# Full pipeline (default): all fingerprinting + anomaly detection
./build/modemprobe --pcap sample.pcap --pipeline full

# Minimal pipeline: L2-L4 parsing only, no fingerprinting or anomaly detection
./build/modemprobe --pcap sample.pcap --pipeline minimal

# Disable ring buffer (direct processing)
./build/modemprobe --pcap sample.pcap --no-ring-buffer
```

### 6. List interfaces

```bash
sudo ./build/modemprobe --list-devices
```

### 7. Help

```bash
./build/modemprobe --help
```

---

## Quick Demo Script

```bash
#!/usr/bin/env bash
set -e

echo "=== Building ModemProbe ==="
cmake -S . -B build
cmake --build build

echo ""
echo "=== Generating sample traffic on loopback ==="
python3 -m http.server 8080 --directory /tmp &
SERVER_PID=$!
sleep 1

echo ""
echo "=== Running live capture on lo for 5 seconds (with WiFi/LTE sim) ==="
sudo ./build/modemprobe --iface lo --seconds 5 --inject-wifi --inject-lte --report demo_live.json &
PROBE_PID=$!

# Generate traffic during capture
for i in $(seq 1 10); do
  curl -s http://127.0.0.1:8080/ > /dev/null 2>&1 || true
  sleep 0.3
done

wait $PROBE_PID 2>/dev/null || true
kill $SERVER_PID 2>/dev/null || true

echo ""
echo "=== Live capture report ==="
cat demo_live.json
echo ""

# If a sample.pcap exists, also demo offline mode
if [ -f sample.pcap ]; then
  echo ""
  echo "=== Running offline pcap processing ==="
  ./build/modemprobe --pcap sample.pcap --report demo_offline.json
  echo ""
  echo "=== Offline report ==="
  cat demo_offline.json
fi

echo ""
echo "=== Demo complete ==="
```

---

## JSON Report Format

The output JSON (`report.json` by default) contains these top-level fields:

| Field | Type | Description |
|---|---|---|
| `protocol_counts` | object | Map of protocol name → packet count |
| `anomaly_counts` | object | Map of anomaly type → occurrence count |
| `anomalies` | array | Array of `{type, count}` anomaly summary objects |
| `anomaly_events_stored` | int | Number of individual anomaly events kept in memory |
| `anomaly_events_dropped` | int | Events dropped due to bounded buffer (max 2000) |
| `performance` | object | `{packets_total, elapsed_seconds, pps, avg_parse_us}` |
| `rtp_streams` | array | Per-SSRC RTP stream summaries |

### Example `report.json`

```json
{
  "protocol_counts": {
    "Ethernet": 1523,
    "IPv4": 1520,
    "TCP": 1100,
    "UDP": 420,
    "HTTP": 85,
    "DNS": 42,
    "RTP": 280,
    "SIP": 5,
    "H264_NAL": 120,
    "WiFi_Beacon": 15,
    "LTE_PDSCH": 10,
    "LTE_PUSCH": 10
  },
  "anomaly_counts": {
    "udp_length_mismatch": 3,
    "tcp_seq_gap": 1,
    "truncated_tcp": 2
  },
  "anomalies": [
    { "type": "udp_length_mismatch", "count": 3 },
    { "type": "tcp_seq_gap", "count": 1 },
    { "type": "truncated_tcp", "count": 2 }
  ],
  "anomaly_events_stored": 6,
  "anomaly_events_dropped": 0,
  "performance": {
    "packets_total": 1523,
    "elapsed_seconds": 5.02,
    "pps": 303.4,
    "avg_parse_us": 1.8
  },
  "rtp_streams": [
    {
      "ssrc": 305419896,
      "received_unique": 275,
      "duplicates": 2,
      "out_of_order": 3,
      "too_old": 0,
      "estimated_lost": 5,
      "first_ts_us": 1700000000000000,
      "last_ts_us": 1700000005000000,
      "saw_h264": true
    }
  ]
}
```

---

## Project Structure

```
ModemProbe/
├── CMakeLists.txt            # Build configuration
├── README.md                 # This file
└── src/
    ├── main.cpp              # Entry point, arg parsing, capture loop, stats, report
    ├── capture_pcap.cpp/h    # libpcap wrapper (live non-blocking + offline)
    ├── raw_socket.cpp/h      # AF_PACKET raw socket capture (Linux, compile flag)
    ├── ring_buffer.h         # Lock-free SPSC ring buffer (header-only)
    ├── pipeline.h            # Configurable processing pipeline (header-only)
    ├── parse.cpp/h           # Ethernet → IPv4 → TCP/UDP dissector
    ├── fingerprint.cpp/h     # HTTP/DNS/RTP/SIP heuristics + H.264 NAL detection
    ├── rtp_stream.cpp/h      # Per-SSRC RTP tracker (loss, wrap, dedup, OOO)
    ├── anomaly.cpp/h         # Anomaly detector (malformed headers, seq gaps)
    ├── wireless_sim.cpp/h    # WiFi 802.11 beacon + LTE PDSCH/PUSCH simulator
    └── report_json.cpp/h     # JSON report writer (jsoncpp)
```

9 `.cpp` files + 10 `.h` files = 19 files total in `src/`.

---

## Architecture & Design Decisions

- **Lock-free SPSC ring buffer** — 1024 pre-allocated slots (2048 bytes each), `std::atomic` head/tail indices, power-of-two masking, zero heap allocation after initialization. Total footprint ~2 MB, well under the 8 MB constraint.
- **Immediate processing option** — when `--no-ring-buffer` is used, packets are parsed inside the capture loop iteration with no copies. Both modes ensure bounded memory.
- **Non-blocking I/O** — both libpcap (`pcap_setnonblock`) and raw socket (`O_NONBLOCK`) modes return immediately when no packet is available.
- **Configurable pipeline** — runtime selection of `full` (all fingerprinting + anomaly detection) or `minimal` (L2-L4 only) processing.
- **Correct RTP gap handling** — uses extended 32-bit sequence numbers + 1024-entry bitmap replay window to distinguish duplicates, out-of-order, and genuine loss. Handles 16-bit wrap-around correctly.
- **Correct TCP gap detection** — 32-bit wrap-aware sequence comparison per RFC 1982.
- **Safe memcmp** — all `memcmp` calls for HTTP DELETE (7 bytes), SIP INVITE (7), REGISTER (9) are length-guarded.
- **Bounded anomaly storage** — max 2000 events in memory; aggregate counts are always accurate.
- **Wireless simulation** — synthetic WiFi beacons and LTE frames are wrapped in Ethernet+IP+UDP so they flow through the standard parser pipeline.
- **No raw pointers to libpcap buffers** — ring buffer copies data; direct mode processes immediately within the loop iteration.

---

## Resume Claim Verification

| Resume Claim | Implementation |
|---|---|
| Raw sockets and libpcap | `capture_pcap.cpp` (libpcap), `raw_socket.cpp` (AF_PACKET behind flag) |
| TCP/IP/UDP dissection | `parse.cpp` — Ethernet→IPv4→TCP/UDP with all fields |
| Protocol fingerprinting (HTTP, DNS, RTP/SIP) | `fingerprint.cpp` — heuristic detection with length guards |
| WiFi 802.11 beacon simulation | `wireless_sim.cpp` — `generate_wifi_beacon()` |
| LTE PDSCH/PUSCH frame patterns | `wireless_sim.cpp` — `generate_lte_frame()` |
| H.264/AVC codec detection | `fingerprint.cpp` — `rtp_payload_has_h264_start_code()` |
| RTP packet sequencing | `rtp_stream.cpp` — bitmap replay window, wrap-around, OOO |
| Lock-free ring buffers | `ring_buffer.h` — SPSC with `std::atomic`, pre-allocated |
| Non-blocking I/O | Both pcap and raw socket backends |
| Minimal memory footprint (<8 MB) | Ring buffer ~2 MB, bounded anomaly storage |
| Configurable processing pipelines | `pipeline.h` — `full` / `minimal` + per-layer toggles |
| JSON reports | `report_json.cpp` — protocol_counts, anomalies, performance, rtp_streams |
| Anomaly detection | `anomaly.cpp` — sequence gaps, malformed headers, UDP mismatch |

---

## License

MIT
