#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modemprobe {

// Basic LTE subframe pattern simulator.
// Generates synthetic PDSCH (downlink) and PUSCH (uplink) frame representations
// for baseband analysis demonstration, mirroring the key scheduling parameters
// a Qualcomm modem would process.

enum class LteDirection : uint8_t {
  Downlink = 0,   // PDSCH
  Uplink   = 1,   // PUSCH
};

struct LteFrameConfig {
  LteDirection direction = LteDirection::Downlink;
  uint16_t rnti           = 0xFFFF;  // Radio Network Temporary Identifier
  uint8_t  mcs            = 10;      // Modulation and Coding Scheme (0-28)
  uint8_t  num_rb         = 50;      // Resource Blocks (1-100 for 20 MHz LTE)
  uint8_t  subframe       = 0;       // Subframe index (0-9)
  uint16_t system_frame   = 0;       // System Frame Number (0-1023)
};

struct LteFrameSummary {
  bool valid = false;
  LteDirection direction = LteDirection::Downlink;
  uint16_t sfn           = 0;
  uint8_t  subframe      = 0;
  uint16_t rnti          = 0;
  uint8_t  mcs           = 0;
  uint8_t  num_rb        = 0;
  size_t   payload_bytes = 0;
};

class LteSimulator {
public:
  // Build a single synthetic LTE subframe with a simplified header.
  static std::vector<uint8_t> build_subframe(const LteFrameConfig& cfg);

  // Generate a full radio frame (10 subframes, one per ms).
  static std::vector<std::vector<uint8_t>> generate_radio_frame(
      uint16_t sfn, uint16_t rnti, LteDirection dir);

  // Parse the simplified subframe header.
  static LteFrameSummary parse_subframe(const uint8_t* data, size_t len);

  // Approximate Transport Block Size (simplified from 3GPP 36.213).
  static size_t approximate_tbs(uint8_t mcs, uint8_t num_rb);
};

} // namespace modemprobe
