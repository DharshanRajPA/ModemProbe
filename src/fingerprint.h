#pragma once

#include "parse.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace modemprobe {

enum class AppProto {
  Unknown = 0,
  HTTP,
  DNS,
  RTP,
  SIP,
};

struct FingerprintResult {
  AppProto proto = AppProto::Unknown;
  bool h264_nal_start = false; // only meaningful for RTP
  std::string detail;          // small optional detail (e.g., HTTP method)
};

// Heuristics only; designed to be safe (never reads past payload_len).
FingerprintResult fingerprint_app(const ParsedPacket& pkt);

// Helpers (exposed for tests later if desired; not required).
bool looks_like_http(const uint8_t* payload, size_t len, std::string* method_out);
bool looks_like_dns(const ParsedPacket& pkt);
bool looks_like_sip(const uint8_t* payload, size_t len);
bool looks_like_rtp(const ParsedPacket& pkt, size_t* rtp_header_len_out);
bool rtp_payload_has_h264_start_code(const uint8_t* p, size_t len);

} // namespace modemprobe

