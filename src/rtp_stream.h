#pragma once

#include <cstdint>
#include <unordered_map>

namespace modemprobe {

// Track per-SSRC stream state and compute loss/gaps robustly:
// - Handles 16-bit wrap-around
// - Ignores duplicates
// - Treats mildly out-of-order packets as reordering (not loss)
// - Corrects "loss" when late/out-of-order packets arrive (within a replay window)
//
// This is not a full RFC3550 implementation; it's a simple, safe demo tracker.
struct RtpStreamState {
  uint32_t ssrc = 0;
  bool initialized = false;

  uint16_t max_seq = 0;          // highest seq observed (in 16-bit space)
  uint32_t cycles = 0;           // how many 0x10000 wraps observed (in units of 0x10000)

  uint32_t base_ext = 0;         // first extended sequence number
  uint32_t highest_ext = 0;      // highest extended sequence number observed

  uint32_t received_unique = 0;  // unique packets within sequence space (excluding duplicates)
  uint32_t duplicates = 0;
  uint32_t out_of_order = 0;
  uint32_t too_old = 0;

  uint32_t estimated_lost = 0;   // computed as expected - received_unique

  uint64_t first_ts_us = 0;
  uint64_t last_ts_us = 0;
  bool saw_h264 = false;

  // Replay window of last 1024 sequence numbers, as a bitmap relative to highest_ext.
  // Bit 0 corresponds to highest_ext, bit 1023 corresponds to highest_ext-1023.
  static constexpr uint32_t kWindowSize = 1024;
  static constexpr uint32_t kWords = kWindowSize / 64;
  uint64_t window[kWords] = {0};
};

struct RtpPacketView {
  bool ok = false;
  uint16_t seq = 0;
  uint32_t ssrc = 0;
};

// Parse minimal RTP header (seq + ssrc). Caller must ensure payload_len >= 12.
RtpPacketView parse_rtp_minimal(const uint8_t* payload, size_t payload_len);

class RtpStreamTracker {
public:
  void on_rtp_packet(const uint8_t* rtp_payload,
                     size_t rtp_len,
                     uint64_t ts_us,
                     bool h264_detected);

  const std::unordered_map<uint32_t, RtpStreamState>& streams() const { return streams_; }

private:
  static bool seq_gt(uint16_t a, uint16_t b);
  static uint16_t seq_diff(uint16_t a, uint16_t b);

  static void window_shift_left(RtpStreamState& s, uint32_t delta);
  static bool window_test(const RtpStreamState& s, uint32_t offset);
  static void window_set(RtpStreamState& s, uint32_t offset);
  static uint32_t compute_estimated_lost(const RtpStreamState& s);

  std::unordered_map<uint32_t, RtpStreamState> streams_;
};

} // namespace modemprobe

