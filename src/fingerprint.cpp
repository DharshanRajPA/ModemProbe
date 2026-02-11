#include "fingerprint.h"

#include <cstring>

namespace modemprobe {
namespace {

static inline bool memeq(const uint8_t* p, const char* s, size_t n) {
  return std::memcmp(p, s, n) == 0;
}

static inline bool has_prefix(const uint8_t* p, size_t len, const char* s) {
  const size_t n = std::strlen(s);
  return len >= n && memeq(p, s, n);
}

} // namespace

bool looks_like_http(const uint8_t* payload, size_t len, std::string* method_out) {
  if (!payload || len < 3) return false;

  // Methods. Important: guard lengths (known bug pattern).
  if (len >= 4 && memeq(payload, "GET ", 4)) {
    if (method_out) *method_out = "GET";
    return true;
  }
  if (len >= 5 && memeq(payload, "POST ", 5)) {
    if (method_out) *method_out = "POST";
    return true;
  }
  if (len >= 4 && memeq(payload, "PUT ", 4)) {
    if (method_out) *method_out = "PUT";
    return true;
  }
  if (len >= 5 && memeq(payload, "HEAD ", 5)) {
    if (method_out) *method_out = "HEAD";
    return true;
  }
  if (len >= 7 && memeq(payload, "DELETE ", 7)) { // guarded
    if (method_out) *method_out = "DELETE";
    return true;
  }
  if (len >= 5 && memeq(payload, "HTTP/", 5)) {
    if (method_out) *method_out = "HTTP_RESPONSE";
    return true;
  }

  return false;
}

bool looks_like_sip(const uint8_t* payload, size_t len) {
  if (!payload || len < 3) return false;

  // SIP request/response line tokens; all length-guarded (known bug pattern).
  if (len >= 4 && memeq(payload, "SIP/", 4)) return true;
  if (len >= 7 && memeq(payload, "INVITE ", 7)) return true;   // "INVITE "
  if (len >= 9 && memeq(payload, "REGISTER ", 9)) return true; // "REGISTER "
  if (len >= 4 && memeq(payload, "ACK ", 4)) return true;
  if (len >= 7 && memeq(payload, "CANCEL ", 7)) return true;
  if (len >= 4 && memeq(payload, "BYE ", 4)) return true;

  // Also accept if it contains a common header prefix near start.
  if (len >= 8 && has_prefix(payload, len, "Via: SIP")) return true;

  return false;
}

bool looks_like_dns(const ParsedPacket& pkt) {
  if (!pkt.has_udp) return false;
  // Classic DNS port 53.
  if (pkt.udp.src_port != 53 && pkt.udp.dst_port != 53) return false;
  // DNS header is 12 bytes.
  if (!pkt.l4_payload || pkt.l4_payload_len < 12) return false;
  return true;
}

bool looks_like_rtp(const ParsedPacket& pkt, size_t* rtp_header_len_out) {
  if (!pkt.has_udp) return false;
  if (!pkt.l4_payload || pkt.l4_payload_len < 12) return false;

  const uint8_t* p = pkt.l4_payload;
  const size_t len = pkt.l4_payload_len;

  const uint8_t v = (p[0] >> 6) & 0x03;
  if (v != 2) return false;

  const uint8_t cc = p[0] & 0x0F;
  const bool x = (p[0] & 0x10) != 0;

  size_t hdr_len = 12 + static_cast<size_t>(cc) * 4;
  if (len < hdr_len) return false;

  if (x) {
    // Extension: 16-bit profile + 16-bit length (in 32-bit words).
    if (len < hdr_len + 4) return false;
    const uint16_t ext_words = static_cast<uint16_t>((p[hdr_len + 2] << 8) | p[hdr_len + 3]);
    hdr_len += 4 + static_cast<size_t>(ext_words) * 4;
    if (len < hdr_len) return false;
  }

  // Heuristic port range: don't require it, but it helps reduce false positives.
  const bool port_ok = (pkt.udp.src_port == 5004 || pkt.udp.dst_port == 5004 ||
                        (pkt.udp.src_port >= 16384 && pkt.udp.src_port <= 32767) ||
                        (pkt.udp.dst_port >= 16384 && pkt.udp.dst_port <= 32767));

  // Payload type sanity (0..127) always true; but reject RTCP (common on odd port) weakly.
  if (!port_ok) {
    // Still accept if header looks sane and UDP payload is not tiny.
    if (len < 16) return false;
  }

  if (rtp_header_len_out) *rtp_header_len_out = hdr_len;
  return true;
}

bool rtp_payload_has_h264_start_code(const uint8_t* p, size_t len) {
  if (!p || len < 4) return false;
  // Scan a small prefix only (avoid expensive scan; good enough for demo).
  const size_t scan = (len < 256) ? len : 256;
  for (size_t i = 0; i + 4 <= scan; ++i) {
    if (p[i] == 0x00 && p[i + 1] == 0x00) {
      if (p[i + 2] == 0x01) return true;                          // 00 00 01
      if (i + 4 <= scan && p[i + 2] == 0x00 && p[i + 3] == 0x01) return true; // 00 00 00 01
    }
  }
  return false;
}

FingerprintResult fingerprint_app(const ParsedPacket& pkt) {
  FingerprintResult r;

  // DNS first (port-based, easy).
  if (looks_like_dns(pkt)) {
    r.proto = AppProto::DNS;
    return r;
  }

  // RTP (UDP). If RTP, also check H.264 start code in RTP payload portion.
  size_t rtp_hdr_len = 0;
  if (looks_like_rtp(pkt, &rtp_hdr_len)) {
    r.proto = AppProto::RTP;
    const uint8_t* rp = pkt.l4_payload + rtp_hdr_len;
    const size_t rlen = (pkt.l4_payload_len >= rtp_hdr_len) ? (pkt.l4_payload_len - rtp_hdr_len) : 0;
    r.h264_nal_start = rtp_payload_has_h264_start_code(rp, rlen);
    return r;
  }

  // SIP (often UDP/5060, but also TCP).
  if (pkt.l4_payload && looks_like_sip(pkt.l4_payload, pkt.l4_payload_len)) {
    r.proto = AppProto::SIP;
    return r;
  }

  // HTTP (usually TCP).
  std::string method;
  if (pkt.l4_payload && looks_like_http(pkt.l4_payload, pkt.l4_payload_len, &method)) {
    r.proto = AppProto::HTTP;
    r.detail = method;
    return r;
  }

  return r;
}

} // namespace modemprobe

