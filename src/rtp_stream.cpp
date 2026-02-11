#include "rtp_stream.h"

#include <cstddef>
#include <cstdint>

namespace modemprobe {
namespace {

static inline uint16_t read_be16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8) | p[1]; }
static inline uint32_t read_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

} // namespace

RtpPacketView parse_rtp_minimal(const uint8_t* payload, size_t payload_len) {
  RtpPacketView v;
  if (!payload || payload_len < 12) return v;
  const uint8_t version = (payload[0] >> 6) & 0x03;
  if (version != 2) return v;
  v.ok = true;
  v.seq = read_be16(payload + 2);
  v.ssrc = read_be32(payload + 8);
  return v;
}

// Sequence-number comparison with wrap-around: "a > b" if a is ahead of b within half-range.
bool RtpStreamTracker::seq_gt(uint16_t a, uint16_t b) {
  return static_cast<uint16_t>(a - b) < 0x8000;
}

uint16_t RtpStreamTracker::seq_diff(uint16_t a, uint16_t b) {
  return static_cast<uint16_t>(a - b);
}

void RtpStreamTracker::window_shift_left(RtpStreamState& s, uint32_t delta) {
  if (delta == 0) return;
  if (delta >= RtpStreamState::kWindowSize) {
    for (uint32_t i = 0; i < RtpStreamState::kWords; ++i) s.window[i] = 0;
    return;
  }

  const uint32_t word_shift = delta / 64;
  const uint32_t bit_shift = delta % 64;

  uint64_t tmp[RtpStreamState::kWords] = {0};
  for (uint32_t i = 0; i < RtpStreamState::kWords; ++i) {
    uint64_t v = 0;
    if (i + word_shift < RtpStreamState::kWords) v = s.window[i + word_shift];
    if (bit_shift != 0) {
      uint64_t v2 = 0;
      if (i + word_shift + 1 < RtpStreamState::kWords) v2 = s.window[i + word_shift + 1];
      v = (v >> bit_shift) | (v2 << (64 - bit_shift));
    }
    tmp[i] = v;
  }
  for (uint32_t i = 0; i < RtpStreamState::kWords; ++i) s.window[i] = tmp[i];
}

bool RtpStreamTracker::window_test(const RtpStreamState& s, uint32_t offset) {
  const uint32_t word = offset / 64;
  const uint32_t bit = offset % 64;
  return (s.window[word] >> bit) & 1ULL;
}

void RtpStreamTracker::window_set(RtpStreamState& s, uint32_t offset) {
  const uint32_t word = offset / 64;
  const uint32_t bit = offset % 64;
  s.window[word] |= (1ULL << bit);
}

uint32_t RtpStreamTracker::compute_estimated_lost(const RtpStreamState& s) {
  if (!s.initialized) return 0;
  const uint32_t expected = (s.highest_ext - s.base_ext) + 1;
  if (s.received_unique >= expected) return 0;
  return expected - s.received_unique;
}

void RtpStreamTracker::on_rtp_packet(const uint8_t* rtp_payload,
                                    size_t rtp_len,
                                    uint64_t ts_us,
                                    bool h264_detected) {
  auto v = parse_rtp_minimal(rtp_payload, rtp_len);
  if (!v.ok) return;

  RtpStreamState& s = streams_[v.ssrc];
  if (!s.initialized) {
    s.ssrc = v.ssrc;
    s.initialized = true;
    s.max_seq = v.seq;
    s.cycles = 0;
    s.base_ext = static_cast<uint32_t>(v.seq);
    s.highest_ext = static_cast<uint32_t>(v.seq);
    s.received_unique = 1;
    s.first_ts_us = ts_us;
    s.last_ts_us = ts_us;
    s.saw_h264 = h264_detected;
    for (uint32_t i = 0; i < RtpStreamState::kWords; ++i) s.window[i] = 0;
    window_set(s, 0); // highest received
    s.estimated_lost = 0;
    return;
  }

  s.last_ts_us = ts_us;
  if (h264_detected) s.saw_h264 = true;

  const uint16_t seq16 = v.seq;

  // Compute extended sequence number relative to max_seq/cycles.
  uint16_t max_seq16 = s.max_seq;
  uint32_t cycles = s.cycles;
  if (seq_gt(seq16, max_seq16) && seq16 < max_seq16) {
    // wrap detected
    cycles += 0x10000u;
  }
  uint32_t ext = cycles + static_cast<uint32_t>(seq16);

  // Advance highest if needed.
  if (ext > s.highest_ext) {
    const uint32_t delta = ext - s.highest_ext;
    window_shift_left(s, delta);
    s.highest_ext = ext;
    s.max_seq = seq16;
    s.cycles = cycles;
    // New highest packet: offset 0.
    if (window_test(s, 0)) {
      s.duplicates++;
    } else {
      window_set(s, 0);
      s.received_unique++;
    }
  } else {
    const uint32_t offset = s.highest_ext - ext;
    if (offset >= RtpStreamState::kWindowSize) {
      s.too_old++;
    } else {
      if (window_test(s, offset)) {
        s.duplicates++;
      } else {
        window_set(s, offset);
        s.received_unique++;
        if (offset != 0) s.out_of_order++;
      }
    }
  }

  s.estimated_lost = compute_estimated_lost(s);
}

} // namespace modemprobe

