#pragma once

#include <pcap/pcap.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modemprobe {

class PcapHandle {
public:
  PcapHandle() = default;
  ~PcapHandle();

  PcapHandle(const PcapHandle&) = delete;
  PcapHandle& operator=(const PcapHandle&) = delete;
  PcapHandle(PcapHandle&& other) noexcept;
  PcapHandle& operator=(PcapHandle&& other) noexcept;

  bool open_live_nonblocking(const std::string& iface,
                             int snaplen,
                             bool promiscuous,
                             int read_timeout_ms,
                             std::string* err);
  bool open_offline(const std::string& pcap_path, std::string* err);
  void close();

  // Returns like pcap_next_ex:
  //  1: got packet (hdr/data set)
  //  0: no packet available right now (non-blocking live)
  // -1: error
  // -2: EOF (offline)
  int next(const pcap_pkthdr** hdr, const uint8_t** data);

  std::string last_error() const;
  bool is_open() const { return handle_ != nullptr; }

  static std::vector<std::string> list_devices(std::string* err);

private:
  pcap_t* handle_ = nullptr;
};

} // namespace modemprobe

