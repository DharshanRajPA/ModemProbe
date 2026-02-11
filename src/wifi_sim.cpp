#include "wifi_sim.h"

#include <cstdio>
#include <cstring>

namespace modemprobe {
namespace {

// 802.11 Frame Control for a Beacon: Type 0 (Mgmt), Subtype 8 (Beacon).
// In little-endian byte order: 0x80 0x00.
static constexpr uint16_t kBeaconFC = 0x0080;

static void write_le16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>(v & 0xFF);
  p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

static uint16_t read_le16(const uint8_t* p) {
  return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

static void write_le64(uint8_t* p, uint64_t v) {
  for (int i = 0; i < 8; ++i)
    p[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
}

} // namespace

// ---------------------------------------------------------------------------
// Build a synthetic 802.11 Beacon frame
// ---------------------------------------------------------------------------
//  MAC Header     : 24 bytes (FC + Duration + Addr1/2/3 + SeqCtrl)
//  Fixed Params   : 12 bytes (Timestamp 8B + Beacon Interval 2B + Capability 2B)
//  Tagged Params  : variable (SSID + Supported Rates + DS Parameter Set)
// ---------------------------------------------------------------------------
std::vector<uint8_t> WifiSimulator::build_beacon_frame(const WifiBeaconInfo& info) {
  std::vector<uint8_t> f;
  f.reserve(128);

  // --- MAC Header (24 bytes) ---
  // Frame Control
  uint8_t fc[2];
  write_le16(fc, kBeaconFC);
  f.push_back(fc[0]);
  f.push_back(fc[1]);

  // Duration / ID
  f.push_back(0x00);
  f.push_back(0x00);

  // Address 1: Destination = broadcast
  for (int i = 0; i < 6; ++i) f.push_back(0xFF);

  // Address 2: Source = BSSID
  for (int i = 0; i < 6; ++i) f.push_back(info.bssid[i]);

  // Address 3: BSSID
  for (int i = 0; i < 6; ++i) f.push_back(info.bssid[i]);

  // Sequence Control
  f.push_back(0x00);
  f.push_back(0x00);

  // --- Fixed Parameters (12 bytes) ---
  // Timestamp (8 bytes, set to 0 for sim)
  uint8_t ts[8];
  write_le64(ts, 0);
  for (int i = 0; i < 8; ++i) f.push_back(ts[i]);

  // Beacon Interval
  uint8_t bi[2];
  write_le16(bi, info.beacon_interval_tu);
  f.push_back(bi[0]);
  f.push_back(bi[1]);

  // Capability Information (ESS bit set)
  f.push_back(0x01);
  f.push_back(0x00);

  // --- Tagged Parameters ---
  // Tag 0: SSID
  f.push_back(0x00);
  f.push_back(static_cast<uint8_t>(info.ssid.size()));
  for (char c : info.ssid)
    f.push_back(static_cast<uint8_t>(c));

  // Tag 1: Supported Rates (802.11b basic rates)
  f.push_back(0x01);
  f.push_back(0x04);
  f.push_back(0x82);   // 1 Mbps   (basic)
  f.push_back(0x84);   // 2 Mbps   (basic)
  f.push_back(0x8B);   // 5.5 Mbps (basic)
  f.push_back(0x96);   // 11 Mbps  (basic)

  // Tag 3: DS Parameter Set (channel)
  f.push_back(0x03);
  f.push_back(0x01);
  f.push_back(info.channel);

  return f;
}

std::vector<std::vector<uint8_t>> WifiSimulator::generate_beacon_batch(size_t count) {
  static const char* kSSIDs[] = {
      "ModemProbe-Lab",   "Qualcomm-Test-5G", "BaseStation-WiFi",
      "LTE-Offload-AP",   "IoT-Sensor-Net",   "Enterprise-WLAN",
      "Guest-Network",    "Debug-AP-01"};
  static constexpr size_t kNumSSIDs = sizeof(kSSIDs) / sizeof(kSSIDs[0]);

  std::vector<std::vector<uint8_t>> batch;
  batch.reserve(count);

  for (size_t i = 0; i < count; ++i) {
    WifiBeaconInfo info;
    info.ssid = kSSIDs[i % kNumSSIDs];
    info.channel = static_cast<uint8_t>((i % 11) + 1); // channels 1-11
    info.beacon_interval_tu = 100;                       // ~102.4 ms

    // Locally-administered unique BSSID per AP
    info.bssid[0] = 0x02;
    info.bssid[1] = 0x00;
    info.bssid[2] = 0x00;
    info.bssid[3] = static_cast<uint8_t>((i >> 16) & 0xFF);
    info.bssid[4] = static_cast<uint8_t>((i >> 8) & 0xFF);
    info.bssid[5] = static_cast<uint8_t>(i & 0xFF);

    batch.push_back(build_beacon_frame(info));
  }
  return batch;
}

WifiSimulator::BeaconSummary WifiSimulator::parse_beacon(const uint8_t* data,
                                                          size_t len) {
  BeaconSummary s;
  // Minimum: 24 (MAC hdr) + 12 (fixed) + 2 (minimal tag header) = 38
  if (!data || len < 38) return s;

  // Verify Frame Control: Management/Beacon
  uint16_t fc = read_le16(data);
  uint8_t type    = (fc >> 2) & 0x03;
  uint8_t subtype = (fc >> 4) & 0x0F;
  if (type != 0 || subtype != 8) return s;

  // BSSID lives at Address 3 (offset 16)
  char bssid_buf[18];
  std::snprintf(bssid_buf, sizeof(bssid_buf),
                "%02X:%02X:%02X:%02X:%02X:%02X",
                data[16], data[17], data[18], data[19], data[20], data[21]);
  s.bssid_str = bssid_buf;

  // Beacon Interval at offset 32
  s.beacon_interval = read_le16(data + 32);

  // Walk tagged parameters starting at offset 36
  size_t pos = 36;
  while (pos + 2 <= len) {
    uint8_t tag_id  = data[pos];
    uint8_t tag_len = data[pos + 1];
    pos += 2;
    if (pos + tag_len > len) break;

    if (tag_id == 0) // SSID
      s.ssid.assign(reinterpret_cast<const char*>(data + pos), tag_len);
    else if (tag_id == 3 && tag_len >= 1) // DS Parameter Set
      s.channel = data[pos];

    pos += tag_len;
  }

  s.valid = true;
  return s;
}

} // namespace modemprobe
