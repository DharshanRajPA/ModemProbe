#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace modemprobe {

// AF_PACKET raw-socket capture backend (Linux only).
// Provides a lower-level alternative to libpcap for direct L2 frame capture,
// demonstrating socket programming for baseband-style packet acquisition.
// Compiled only when MODEMPROBE_ENABLE_RAW_SOCKET is defined.

class RawSocketCapture {
public:
  RawSocketCapture() = default;
  ~RawSocketCapture();

  RawSocketCapture(const RawSocketCapture&) = delete;
  RawSocketCapture& operator=(const RawSocketCapture&) = delete;

  bool open(const std::string& iface, std::string* err);
  void close();

  // Non-blocking receive. Returns bytes read (>0), 0 if no data, -1 on error.
  int recv_packet(uint8_t* buf, size_t buf_size);

  bool is_open() const { return fd_ >= 0; }
  std::string last_error() const { return last_err_; }

  static std::vector<std::string> list_interfaces(std::string* err);

private:
  int fd_ = -1;
  std::string last_err_;
};

} // namespace modemprobe
