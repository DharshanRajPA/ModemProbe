#pragma once
// Minimal AF_PACKET raw socket capture backend (Linux only).
// Enabled at compile time with -DMODEMPROBE_ENABLE_RAW_SOCKET=1.
// Falls back gracefully to a stub on non-Linux or when disabled.

#include <cstddef>
#include <cstdint>
#include <string>

namespace modemprobe {

class RawSocketCapture {
public:
  RawSocketCapture() = default;
  ~RawSocketCapture();

  RawSocketCapture(const RawSocketCapture&) = delete;
  RawSocketCapture& operator=(const RawSocketCapture&) = delete;

  // Open a raw socket on the given interface. Returns false on error.
  bool open(const std::string& iface, std::string* err);

  // Set non-blocking mode. Returns false on error.
  bool set_nonblocking(std::string* err);

  // Receive one packet. Returns:
  //  >0: bytes received (data written to buf)
  //   0: no packet available (non-blocking)
  //  -1: error
  int recv_packet(uint8_t* buf, size_t buf_size, std::string* err);

  void close();
  bool is_open() const;

private:
  int fd_ = -1;
};

} // namespace modemprobe
