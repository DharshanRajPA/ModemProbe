#pragma once

#include "parse.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace modemprobe {

struct AnomalyEvent {
  uint64_t ts_us = 0;
  std::string type;
  std::string detail;
};

class AnomalyCollector {
public:
  // Bounded storage: keep up to max_events events, plus aggregate counts for everything.
  explicit AnomalyCollector(size_t max_events = 2000) : max_events_(max_events) {}

  void set_current_ts(uint64_t ts_us) { current_ts_us_ = ts_us; }
  static void parse_add(void* user, const char* type);

  void add(const std::string& type, uint64_t ts_us, const std::string& detail = {});

  // TCP gap detection (simple heuristic, per-direction flow).
  void on_tcp_packet(const ParsedPacket& pkt, uint64_t ts_us);

  const std::unordered_map<std::string, uint64_t>& counts() const { return counts_; }
  const std::vector<AnomalyEvent>& events() const { return events_; }
  uint64_t dropped_events() const { return dropped_events_; }

private:
  struct FlowKey {
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;

    bool operator==(const FlowKey& o) const {
      return src_ip == o.src_ip && dst_ip == o.dst_ip && src_port == o.src_port && dst_port == o.dst_port;
    }
  };

  struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const noexcept {
      // Simple mix; good enough for demo.
      size_t h = static_cast<size_t>(k.src_ip) * 1315423911u;
      h ^= static_cast<size_t>(k.dst_ip) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
      h ^= (static_cast<size_t>(k.src_port) << 16) | k.dst_port;
      return h;
    }
  };

  struct TcpFlowState {
    bool initialized = false;
    uint32_t highest_seq_end = 0; // seq + payload_len (and SYN/FIN contributions) in modulo-32 space
  };

  static bool seq32_gt(uint32_t a, uint32_t b);     // wrap-aware compare
  static uint32_t seq32_diff(uint32_t a, uint32_t b); // a-b mod 2^32

  size_t max_events_ = 2000;
  uint64_t current_ts_us_ = 0;

  std::unordered_map<std::string, uint64_t> counts_;
  std::vector<AnomalyEvent> events_;
  uint64_t dropped_events_ = 0;

  std::unordered_map<FlowKey, TcpFlowState, FlowKeyHash> tcp_flows_;
};

} // namespace modemprobe

