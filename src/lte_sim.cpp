#include "lte_sim.h"

#include <algorithm>
#include <cstring>

namespace modemprobe {
namespace {

// Simplified subframe header layout (demonstration format):
//   Bytes  0-1 : Magic 0x4C54 ("LT")
//   Byte   2   : Direction (0=DL/PDSCH, 1=UL/PUSCH)
//   Bytes  3-4 : System Frame Number (big-endian)
//   Byte   5   : Subframe index (0-9)
//   Bytes  6-7 : RNTI (big-endian)
//   Byte   8   : MCS
//   Byte   9   : Number of Resource Blocks
//   Bytes 10-11: Payload length (big-endian)
//   Bytes 12+  : Payload (simulated transport block data)

static constexpr size_t   kHeaderSize = 12;
static constexpr uint16_t kMagic      = 0x4C54; // "LT"

static void write_be16(uint8_t* p, uint16_t v) {
  p[0] = static_cast<uint8_t>((v >> 8) & 0xFF);
  p[1] = static_cast<uint8_t>(v & 0xFF);
}

static uint16_t read_be16(const uint8_t* p) {
  return (static_cast<uint16_t>(p[0]) << 8) | p[1];
}

} // namespace

// Highly simplified TBS approximation.
// Real LTE uses 3GPP 36.213 lookup tables; for demo we approximate:
//   bits ≈ num_rb × modulation_order × coding_rate × 12 subcarriers × 14 symbols
size_t LteSimulator::approximate_tbs(uint8_t mcs, uint8_t num_rb) {
  double mod_order;
  if (mcs <= 9)       mod_order = 2.0;  // QPSK
  else if (mcs <= 16) mod_order = 4.0;  // 16-QAM
  else                mod_order = 6.0;  // 64-QAM

  double coding_rate = 0.4 + (static_cast<double>(mcs) / 28.0) * 0.5;
  double bits = static_cast<double>(num_rb) * mod_order * coding_rate * 12.0 * 14.0;
  return std::max<size_t>(static_cast<size_t>(bits / 8.0), 1);
}

std::vector<uint8_t> LteSimulator::build_subframe(const LteFrameConfig& cfg) {
  size_t tbs = approximate_tbs(cfg.mcs, cfg.num_rb);
  std::vector<uint8_t> frame(kHeaderSize + tbs, 0);

  write_be16(frame.data() + 0, kMagic);
  frame[2] = static_cast<uint8_t>(cfg.direction);
  write_be16(frame.data() + 3, cfg.system_frame);
  frame[5] = cfg.subframe;
  write_be16(frame.data() + 6, cfg.rnti);
  frame[8] = cfg.mcs;
  frame[9] = cfg.num_rb;
  write_be16(frame.data() + 10, static_cast<uint16_t>(std::min<size_t>(tbs, 0xFFFF)));

  // Fill payload with a repeating pattern (simulated transport block).
  for (size_t i = 0; i < tbs; ++i)
    frame[kHeaderSize + i] = static_cast<uint8_t>((i * 7 + cfg.subframe) & 0xFF);

  return frame;
}

std::vector<std::vector<uint8_t>> LteSimulator::generate_radio_frame(
    uint16_t sfn, uint16_t rnti, LteDirection dir) {
  std::vector<std::vector<uint8_t>> subframes;
  subframes.reserve(10);

  for (uint8_t sf = 0; sf < 10; ++sf) {
    LteFrameConfig cfg;
    cfg.direction    = dir;
    cfg.system_frame = sfn;
    cfg.subframe     = sf;
    cfg.rnti         = rnti;
    cfg.mcs          = static_cast<uint8_t>(10 + (sf % 5)); // vary MCS per subframe
    cfg.num_rb       = 50;                                    // 20 MHz bandwidth
    subframes.push_back(build_subframe(cfg));
  }
  return subframes;
}

LteFrameSummary LteSimulator::parse_subframe(const uint8_t* data, size_t len) {
  LteFrameSummary s;
  if (!data || len < kHeaderSize) return s;

  uint16_t magic = read_be16(data + 0);
  if (magic != kMagic) return s;

  s.valid         = true;
  s.direction     = static_cast<LteDirection>(data[2]);
  s.sfn           = read_be16(data + 3);
  s.subframe      = data[5];
  s.rnti          = read_be16(data + 6);
  s.mcs           = data[8];
  s.num_rb        = data[9];
  s.payload_bytes = read_be16(data + 10);
  return s;
}

} // namespace modemprobe
