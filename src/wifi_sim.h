#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modemprobe {

// WiFi 802.11 beacon frame simulator.
// Generates synthetic beacon frames that mirror real AP advertisements,
// demonstrating understanding of the 802.11 management frame format used
// in baseband WiFi processing.

struct WifiBeaconInfo {
  std::string ssid;
  uint8_t channel;
  uint16_t beacon_interval_tu;   // Time Units (1 TU = 1024 us)
  uint8_t bssid[6];
};

class WifiSimulator {
public:
  // Build a raw 802.11 beacon frame (without FCS).
  static std::vector<uint8_t> build_beacon_frame(const WifiBeaconInfo& info);

  // Generate a batch of beacons from multiple simulated APs.
  static std::vector<std::vector<uint8_t>> generate_beacon_batch(size_t count);

  // Parsed summary of a beacon frame (for display / report).
  struct BeaconSummary {
    bool valid = false;
    std::string ssid;
    uint8_t channel = 0;
    uint16_t beacon_interval = 0;
    std::string bssid_str;
  };

  // Parse & describe a beacon frame.
  static BeaconSummary parse_beacon(const uint8_t* data, size_t len);
};

} // namespace modemprobe
