#pragma once

#include <cstddef>
#include <cstdint>

namespace modemprobe {

struct ParseAnomalies {
  void (*add)(void* user, const char* type) = nullptr;
  void* user = nullptr;
};

inline void add_anomaly(const ParseAnomalies* a, const char* type) {
  if (a && a->add) a->add(a->user, type);
}

struct EthernetView {
  bool ok = false;
  uint16_t ethertype = 0; // host order
};

struct IPv4View {
  bool ok = false;
  uint8_t ihl_bytes = 0;
  uint16_t total_len = 0; // host order
  uint8_t protocol = 0;   // IPPROTO_TCP=6, IPPROTO_UDP=17
  uint32_t src_ip = 0;    // host order
  uint32_t dst_ip = 0;    // host order
};

struct TcpView {
  bool ok = false;
  uint16_t src_port = 0; // host order
  uint16_t dst_port = 0; // host order
  uint32_t seq = 0;      // host order
  uint32_t ack = 0;      // host order
  uint8_t data_offset_bytes = 0;
  uint8_t flags = 0; // low 6 bits (FIN..URG) + others if needed
};

struct UdpView {
  bool ok = false;
  uint16_t src_port = 0; // host order
  uint16_t dst_port = 0; // host order
  uint16_t length = 0;   // host order (header+payload)
};

struct ParsedPacket {
  EthernetView eth;
  IPv4View ip4;
  TcpView tcp;
  UdpView udp;

  bool has_eth = false;
  bool has_ip4 = false;
  bool has_tcp = false;
  bool has_udp = false;

  const uint8_t* l4_payload = nullptr;
  size_t l4_payload_len = 0;
};

// Parses Ethernet -> IPv4 -> TCP/UDP and sets l4_payload/l4_payload_len to the L4 payload.
// Never stores pointers for later use; the returned pointers are valid only while the caller
// keeps the packet buffer alive (i.e., inside the capture loop iteration).
bool parse_ethernet_ipv4_tcpudp(const uint8_t* data,
                                size_t caplen,
                                ParsedPacket& out,
                                const ParseAnomalies* anomalies);

} // namespace modemprobe

