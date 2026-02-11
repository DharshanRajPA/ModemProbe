#include "wireless_sim.h"

#include <cstring>

namespace modemprobe {
namespace {

// Build a minimal Ethernet II + IPv4 + UDP wrapper around an arbitrary payload.
// Uses a reserved private IP range (10.0.0.x) and a high destination port (9999)
// so these synthetic frames are easily distinguishable but still parseable.
static std::vector<uint8_t> wrap_in_eth_ip_udp(const uint8_t* payload,
                                                size_t payload_len,
                                                uint16_t udp_dst_port) {
  // Ethernet header: 14 bytes
  // IPv4 header: 20 bytes (no options)
  // UDP header: 8 bytes
  const size_t total = 14 + 20 + 8 + payload_len;
  std::vector<uint8_t> pkt(total, 0);
  uint8_t* p = pkt.data();

  // ── Ethernet II ──
  // dst MAC: broadcast
  std::memset(p, 0xFF, 6);
  // src MAC: locally-administered
  p[6] = 0x02; p[7] = 0x00; p[8] = 0x00; p[9] = 0x00; p[10] = 0x00; p[11] = 0x01;
  // EtherType: IPv4 (0x0800)
  p[12] = 0x08; p[13] = 0x00;

  // ── IPv4 ──
  uint8_t* ip = p + 14;
  ip[0] = 0x45;                       // version=4, IHL=5
  ip[1] = 0x00;                       // DSCP/ECN
  const uint16_t ip_total = static_cast<uint16_t>(20 + 8 + payload_len);
  ip[2] = static_cast<uint8_t>(ip_total >> 8);
  ip[3] = static_cast<uint8_t>(ip_total & 0xFF);
  ip[4] = 0x00; ip[5] = 0x01;        // identification
  ip[6] = 0x00; ip[7] = 0x00;        // flags + fragment offset
  ip[8] = 64;                         // TTL
  ip[9] = 17;                         // protocol = UDP
  ip[10] = 0; ip[11] = 0;            // checksum (0 = skip)
  // src IP: 10.0.0.1
  ip[12] = 10; ip[13] = 0; ip[14] = 0; ip[15] = 1;
  // dst IP: 10.0.0.255
  ip[16] = 10; ip[17] = 0; ip[18] = 0; ip[19] = 255;

  // ── UDP ──
  uint8_t* udp = ip + 20;
  const uint16_t src_port = 9998;
  udp[0] = static_cast<uint8_t>(src_port >> 8);
  udp[1] = static_cast<uint8_t>(src_port & 0xFF);
  udp[2] = static_cast<uint8_t>(udp_dst_port >> 8);
  udp[3] = static_cast<uint8_t>(udp_dst_port & 0xFF);
  const uint16_t udp_len = static_cast<uint16_t>(8 + payload_len);
  udp[4] = static_cast<uint8_t>(udp_len >> 8);
  udp[5] = static_cast<uint8_t>(udp_len & 0xFF);
  udp[6] = 0; udp[7] = 0;            // checksum (0 = skip)

  // ── Payload ──
  std::memcpy(udp + 8, payload, payload_len);

  return pkt;
}

} // anonymous namespace

// ═══════════════════════════ WiFi 802.11 Beacon ═════════════════════════════

std::vector<uint8_t> generate_wifi_beacon(const WifiBeaconParams& params,
                                          uint32_t sequence_number) {
  // Build a simplified 802.11 Beacon frame body (not a full radiotap capture,
  // but enough to demonstrate beacon structure for baseband analysis).
  //
  // Layout:
  //   "WIFI_BEACON:" tag (12 bytes) -- for easy detection in our pipeline
  //   Frame Control (2 bytes): 0x80 0x00 (beacon)
  //   Duration (2 bytes): 0x00 0x00
  //   Destination (6 bytes): FF:FF:FF:FF:FF:FF (broadcast)
  //   Source / BSSID (6 bytes): from params
  //   BSSID (6 bytes): same
  //   Sequence Control (2 bytes)
  //   Fixed parameters (12 bytes): timestamp(8) + interval(2) + capability(2)
  //   Tagged parameters:
  //     SSID IE: tag=0, len, ssid bytes
  //     DS Parameter Set IE: tag=3, len=1, channel

  const char* tag = "WIFI_BEACON:";
  const size_t tag_len = 12;
  const size_t ssid_len = params.ssid.size();
  const size_t fixed_len = 2 + 2 + 6 + 6 + 6 + 2 + 12; // 36 bytes
  const size_t ssid_ie_len = 2 + ssid_len;               // tag + len + data
  const size_t ds_ie_len = 3;                             // tag + len + channel
  const size_t body_len = tag_len + fixed_len + ssid_ie_len + ds_ie_len;

  std::vector<uint8_t> body(body_len, 0);
  uint8_t* b = body.data();
  size_t off = 0;

  // Tag
  std::memcpy(b + off, tag, tag_len);
  off += tag_len;

  // Frame Control: beacon
  b[off++] = 0x80;
  b[off++] = 0x00;

  // Duration
  b[off++] = 0x00;
  b[off++] = 0x00;

  // Destination: broadcast
  std::memset(b + off, 0xFF, 6);
  off += 6;

  // Source: BSSID
  std::memcpy(b + off, params.bssid, 6);
  off += 6;

  // BSSID again
  std::memcpy(b + off, params.bssid, 6);
  off += 6;

  // Sequence Control
  const uint16_t seq_ctrl = static_cast<uint16_t>((sequence_number & 0x0FFF) << 4);
  b[off++] = static_cast<uint8_t>(seq_ctrl & 0xFF);
  b[off++] = static_cast<uint8_t>(seq_ctrl >> 8);

  // Fixed: Timestamp (8 bytes, zeroed for sim)
  off += 8;

  // Beacon Interval
  b[off++] = static_cast<uint8_t>(params.beacon_interval & 0xFF);
  b[off++] = static_cast<uint8_t>(params.beacon_interval >> 8);

  // Capability Info
  b[off++] = 0x01;   // ESS
  b[off++] = 0x00;

  // SSID IE
  b[off++] = 0;      // tag number: SSID
  b[off++] = static_cast<uint8_t>(ssid_len);
  std::memcpy(b + off, params.ssid.data(), ssid_len);
  off += ssid_len;

  // DS Parameter Set IE
  b[off++] = 3;      // tag number: DS Parameter Set
  b[off++] = 1;
  b[off++] = params.channel;

  // Wrap in Ethernet+IP+UDP envelope (port 9999 = wifi sim)
  return wrap_in_eth_ip_udp(body.data(), body.size(), 9999);
}

bool is_simulated_wifi_beacon(const uint8_t* payload, size_t len) {
  if (!payload || len < 12) return false;
  return std::memcmp(payload, "WIFI_BEACON:", 12) == 0;
}

// ═══════════════════════════ LTE PDSCH/PUSCH ════════════════════════════════

std::vector<uint8_t> generate_lte_frame(const LteFrameParams& params,
                                        uint32_t frame_number) {
  // Layout:
  //   "LTE_PDSCH:" or "LTE_PUSCH:" tag (10 bytes)
  //   Frame number (4 bytes, big-endian)
  //   RNTI (2 bytes, big-endian)
  //   Subframe (1 byte)
  //   Num PRB (1 byte)
  //   MCS (1 byte)
  //   Direction (1 byte)
  //   Dummy transport block data (num_prb * 12 bytes, simulating RE mapping)

  const char* tag = (params.direction == LteDirection::Downlink) ? "LTE_PDSCH:" : "LTE_PUSCH:";
  const size_t tag_len = 10;
  const size_t hdr_len = tag_len + 4 + 2 + 1 + 1 + 1 + 1; // 20 bytes
  const size_t tb_size = static_cast<size_t>(params.num_prb) * 12; // resource elements
  const size_t body_len = hdr_len + tb_size;

  std::vector<uint8_t> body(body_len, 0);
  uint8_t* b = body.data();
  size_t off = 0;

  // Tag
  std::memcpy(b + off, tag, tag_len);
  off += tag_len;

  // Frame number (big-endian)
  b[off++] = static_cast<uint8_t>((frame_number >> 24) & 0xFF);
  b[off++] = static_cast<uint8_t>((frame_number >> 16) & 0xFF);
  b[off++] = static_cast<uint8_t>((frame_number >>  8) & 0xFF);
  b[off++] = static_cast<uint8_t>((frame_number      ) & 0xFF);

  // RNTI
  b[off++] = static_cast<uint8_t>((params.rnti >> 8) & 0xFF);
  b[off++] = static_cast<uint8_t>((params.rnti     ) & 0xFF);

  // Subframe, PRB, MCS, Direction
  b[off++] = params.subframe;
  b[off++] = params.num_prb;
  b[off++] = params.mcs;
  b[off++] = static_cast<uint8_t>(params.direction);

  // Dummy transport block: fill with a pattern simulating QPSK-modulated data
  for (size_t i = 0; i < tb_size; ++i) {
    b[off + i] = static_cast<uint8_t>((frame_number + i) & 0xFF);
  }

  // Wrap in Ethernet+IP+UDP envelope (port 9998 = lte sim)
  return wrap_in_eth_ip_udp(body.data(), body.size(), 9998);
}

bool is_simulated_lte_frame(const uint8_t* payload, size_t len,
                            LteDirection* dir_out) {
  if (!payload || len < 10) return false;
  if (std::memcmp(payload, "LTE_PDSCH:", 10) == 0) {
    if (dir_out) *dir_out = LteDirection::Downlink;
    return true;
  }
  if (std::memcmp(payload, "LTE_PUSCH:", 10) == 0) {
    if (dir_out) *dir_out = LteDirection::Uplink;
    return true;
  }
  return false;
}

} // namespace modemprobe
