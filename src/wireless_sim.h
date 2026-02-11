#pragma once
// Wireless protocol simulation for demo/testing purposes.
// Generates synthetic WiFi 802.11 beacon frames and basic LTE PDSCH/PUSCH
// frame patterns, simulating Qualcomm modem baseband traffic for analysis.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modemprobe {

// ──────────────── WiFi 802.11 Beacon Simulation ─────────────────────────────

struct WifiBeaconParams {
  uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
  std::string ssid = "ModemProbe_Demo";
  uint8_t channel = 6;
  uint16_t beacon_interval = 100; // TU (1 TU = 1024 us)
};

// Generate a synthetic 802.11 beacon frame wrapped in a fake Ethernet+IP+UDP
// envelope so it can flow through our standard Ethernet parser pipeline.
// The UDP payload contains a tagged "WIFI_BEACON:" prefix + the raw 802.11 frame.
// Returns the full packet bytes ready to push into the ring buffer.
std::vector<uint8_t> generate_wifi_beacon(const WifiBeaconParams& params,
                                          uint32_t sequence_number);

// Inspect a UDP payload and detect our synthetic WiFi beacon marker.
bool is_simulated_wifi_beacon(const uint8_t* payload, size_t len);

// ──────────────── LTE PDSCH/PUSCH Simulation ────────────────────────────────

enum class LteDirection : uint8_t {
  Downlink = 0, // PDSCH
  Uplink = 1,   // PUSCH
};

struct LteFrameParams {
  LteDirection direction = LteDirection::Downlink;
  uint16_t rnti = 1;         // Radio Network Temporary Identifier
  uint8_t subframe = 0;      // 0-9
  uint8_t num_prb = 50;      // number of Physical Resource Blocks (1-100)
  uint8_t mcs = 10;          // Modulation and Coding Scheme (0-28)
};

// Generate a synthetic LTE PDSCH or PUSCH pattern wrapped in Ethernet+IP+UDP.
// UDP payload: "LTE_PDSCH:" or "LTE_PUSCH:" prefix + binary parameters + dummy data.
std::vector<uint8_t> generate_lte_frame(const LteFrameParams& params,
                                        uint32_t frame_number);

// Inspect a UDP payload and detect our synthetic LTE frame marker.
bool is_simulated_lte_frame(const uint8_t* payload, size_t len,
                            LteDirection* dir_out = nullptr);

} // namespace modemprobe
