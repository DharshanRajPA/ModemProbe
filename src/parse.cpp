#include "parse.h"

#include <cstring>

namespace modemprobe {
namespace {

static inline uint16_t read_be16(const uint8_t* p) { return static_cast<uint16_t>(p[0] << 8) | p[1]; }
static inline uint32_t read_be32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

} // namespace

bool parse_ethernet_ipv4_tcpudp(const uint8_t* data,
                                size_t caplen,
                                ParsedPacket& out,
                                const ParseAnomalies* anomalies) {
  out = ParsedPacket{};
  if (!data || caplen < 14) {
    add_anomaly(anomalies, "truncated_ethernet");
    return false;
  }

  // Ethernet II
  out.has_eth = true;
  out.eth.ok = true;
  out.eth.ethertype = read_be16(data + 12);
  if (out.eth.ethertype != 0x0800) {
    // Only IPv4 is in scope for this prototype.
    return true;
  }

  // IPv4 header starts at offset 14
  const size_t ip_off = 14;
  if (caplen < ip_off + 20) {
    add_anomaly(anomalies, "truncated_ipv4");
    return true;
  }

  const uint8_t ver_ihl = data[ip_off + 0];
  const uint8_t version = (ver_ihl >> 4) & 0x0F;
  const uint8_t ihl_words = ver_ihl & 0x0F;
  const uint8_t ihl_bytes = static_cast<uint8_t>(ihl_words * 4);
  if (version != 4 || ihl_bytes < 20) {
    add_anomaly(anomalies, "malformed_ipv4_header");
    return true;
  }
  if (caplen < ip_off + ihl_bytes) {
    add_anomaly(anomalies, "truncated_ipv4");
    return true;
  }

  const uint16_t total_len = read_be16(data + ip_off + 2);
  if (total_len < ihl_bytes) {
    add_anomaly(anomalies, "malformed_ipv4_total_length");
    return true;
  }

  out.has_ip4 = true;
  out.ip4.ok = true;
  out.ip4.ihl_bytes = ihl_bytes;
  out.ip4.total_len = total_len;
  out.ip4.protocol = data[ip_off + 9];
  out.ip4.src_ip = read_be32(data + ip_off + 12);
  out.ip4.dst_ip = read_be32(data + ip_off + 16);

  const size_t ip_payload_off = ip_off + ihl_bytes;
  if (caplen < ip_payload_off) {
    add_anomaly(anomalies, "truncated_ipv4");
    return true;
  }

  // total_len is the on-wire IP length. caplen might be smaller (snaplen truncation).
  const size_t ip_available = caplen - ip_off;
  const size_t ip_bytes_captured = (total_len <= ip_available) ? static_cast<size_t>(total_len) : ip_available;
  if (ip_bytes_captured < ihl_bytes) {
    add_anomaly(anomalies, "truncated_ipv4");
    return true;
  }
  const size_t l4_bytes_captured = ip_bytes_captured - ihl_bytes;

  if (out.ip4.protocol == 6 /*TCP*/) {
    if (l4_bytes_captured < 20) {
      add_anomaly(anomalies, "truncated_tcp");
      return true;
    }

    const uint8_t* tcp = data + ip_payload_off;
    const uint16_t src_port = read_be16(tcp + 0);
    const uint16_t dst_port = read_be16(tcp + 2);
    const uint32_t seq = read_be32(tcp + 4);
    const uint32_t ack = read_be32(tcp + 8);
    const uint8_t data_off_words = (tcp[12] >> 4) & 0x0F;
    const uint8_t tcp_hdr_bytes = static_cast<uint8_t>(data_off_words * 4);
    const uint8_t flags = tcp[13];

    if (tcp_hdr_bytes < 20) {
      add_anomaly(anomalies, "malformed_tcp_header");
      return true;
    }
    if (l4_bytes_captured < tcp_hdr_bytes) {
      add_anomaly(anomalies, "truncated_tcp");
      return true;
    }

    out.has_tcp = true;
    out.tcp.ok = true;
    out.tcp.src_port = src_port;
    out.tcp.dst_port = dst_port;
    out.tcp.seq = seq;
    out.tcp.ack = ack;
    out.tcp.data_offset_bytes = tcp_hdr_bytes;
    out.tcp.flags = flags;

    out.l4_payload = tcp + tcp_hdr_bytes;
    out.l4_payload_len = l4_bytes_captured - tcp_hdr_bytes;
    return true;
  }

  if (out.ip4.protocol == 17 /*UDP*/) {
    if (l4_bytes_captured < 8) {
      add_anomaly(anomalies, "truncated_udp");
      return true;
    }

    const uint8_t* udp = data + ip_payload_off;
    const uint16_t src_port = read_be16(udp + 0);
    const uint16_t dst_port = read_be16(udp + 2);
    const uint16_t udp_len = read_be16(udp + 4);

    if (udp_len < 8) {
      add_anomaly(anomalies, "malformed_udp_length");
      return true;
    }

    // Compare UDP header length field to captured L4 bytes; tolerate truncation by snaplen.
    if (udp_len != static_cast<uint16_t>(l4_bytes_captured) && udp_len <= l4_bytes_captured) {
      // udp_len smaller than captured -> extra bytes, suspicious.
      add_anomaly(anomalies, "udp_length_mismatch");
    }
    if (udp_len > l4_bytes_captured) {
      add_anomaly(anomalies, "truncated_udp");
      // Still parse what we have.
    }

    out.has_udp = true;
    out.udp.ok = true;
    out.udp.src_port = src_port;
    out.udp.dst_port = dst_port;
    out.udp.length = udp_len;

    out.l4_payload = udp + 8;
    const size_t udp_payload_captured = (l4_bytes_captured >= 8) ? (l4_bytes_captured - 8) : 0;
    out.l4_payload_len = udp_payload_captured;
    return true;
  }

  return true;
}

} // namespace modemprobe

