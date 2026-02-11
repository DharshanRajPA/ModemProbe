#include "anomaly.h"

#include <algorithm>
#include <sstream>

namespace modemprobe {

void AnomalyCollector::parse_add(void* user, const char* type) {
  auto* self = reinterpret_cast<AnomalyCollector*>(user);
  if (!self || !type) return;
  self->add(type, self->current_ts_us_);
}

void AnomalyCollector::add(const std::string& type, uint64_t ts_us, const std::string& detail) {
  counts_[type]++;
  if (events_.size() < max_events_) {
    events_.push_back(AnomalyEvent{ts_us, type, detail});
  } else {
    dropped_events_++;
  }
}

bool AnomalyCollector::seq32_gt(uint32_t a, uint32_t b) {
  return static_cast<uint32_t>(a - b) < 0x80000000u;
}

uint32_t AnomalyCollector::seq32_diff(uint32_t a, uint32_t b) { return static_cast<uint32_t>(a - b); }

void AnomalyCollector::on_tcp_packet(const ParsedPacket& pkt, uint64_t ts_us) {
  if (!pkt.has_tcp || !pkt.has_ip4) return;

  const uint32_t seq = pkt.tcp.seq;
  const bool syn = (pkt.tcp.flags & 0x02) != 0;
  const bool fin = (pkt.tcp.flags & 0x01) != 0;

  // TCP sequence space advances by payload length plus SYN/FIN (each consumes 1).
  uint32_t seg_len = static_cast<uint32_t>(pkt.l4_payload_len);
  if (syn) seg_len += 1;
  if (fin) seg_len += 1;
  const uint32_t seq_end = seq + seg_len;

  FlowKey k;
  k.src_ip = pkt.ip4.src_ip;
  k.dst_ip = pkt.ip4.dst_ip;
  k.src_port = pkt.tcp.src_port;
  k.dst_port = pkt.tcp.dst_port;

  TcpFlowState& st = tcp_flows_[k];
  if (!st.initialized) {
    st.initialized = true;
    st.highest_seq_end = seq_end;
    return;
  }

  // If this segment starts ahead of the highest seen end, we have a gap.
  // Wrap-aware compare via seq32_gt.
  if (seq32_gt(seq, st.highest_seq_end)) {
    const uint32_t gap = seq32_diff(seq, st.highest_seq_end);
    // Filter out absurd gaps caused by misclassification.
    if (gap > 0 && gap < (16u * 1024u * 1024u)) {
      std::ostringstream oss;
      oss << "gap_bytes=" << gap;
      add("tcp_seq_gap", ts_us, oss.str());
    }
    st.highest_seq_end = seq_end;
    return;
  }

  // Overlap/out-of-order/duplicate. If this extends beyond highest end, update it.
  if (seq32_gt(seq_end, st.highest_seq_end)) {
    st.highest_seq_end = seq_end;
  }
}

} // namespace modemprobe

