#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace modemprobe {

struct RtpStreamSummary {
  uint32_t ssrc = 0;
  uint32_t received_unique = 0;
  uint32_t duplicates = 0;
  uint32_t out_of_order = 0;
  uint32_t too_old = 0;
  uint32_t estimated_lost = 0;
  uint64_t first_ts_us = 0;
  uint64_t last_ts_us = 0;
  bool saw_h264 = false;
};

struct ReportData {
  std::unordered_map<std::string, uint64_t> protocol_counts;
  std::unordered_map<std::string, uint64_t> anomaly_counts;
  uint64_t anomaly_events_stored = 0;
  uint64_t anomaly_events_dropped = 0;

  uint64_t packets_total = 0;
  double elapsed_seconds = 0.0;
  double pps = 0.0;
  double avg_parse_us = 0.0;

  std::vector<RtpStreamSummary> rtp_streams;
};

bool write_report_json(const std::string& path, const ReportData& r, std::string* err);

} // namespace modemprobe

