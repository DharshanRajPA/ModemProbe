#include "raw_socket.h"

#ifdef MODEMPROBE_ENABLE_RAW_SOCKET
// ─────────────── Real implementation (Linux AF_PACKET) ──────────────────────

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <unistd.h>

namespace modemprobe {

RawSocketCapture::~RawSocketCapture() { close(); }

bool RawSocketCapture::open(const std::string& iface, std::string* err) {
  close();

  // Create raw socket: AF_PACKET, SOCK_RAW captures full Ethernet frames.
  fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd_ < 0) {
    if (err) *err = std::string("socket(AF_PACKET) failed: ") + std::strerror(errno);
    return false;
  }

  // Bind to specific interface.
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
  if (::ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
    if (err) *err = std::string("ioctl SIOCGIFINDEX failed: ") + std::strerror(errno);
    close();
    return false;
  }

  struct sockaddr_ll sll;
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = ifr.ifr_ifindex;

  if (::bind(fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
    if (err) *err = std::string("bind(AF_PACKET) failed: ") + std::strerror(errno);
    close();
    return false;
  }

  return true;
}

bool RawSocketCapture::set_nonblocking(std::string* err) {
  if (fd_ < 0) {
    if (err) *err = "socket not open";
    return false;
  }
  int flags = ::fcntl(fd_, F_GETFL, 0);
  if (flags < 0 || ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK) < 0) {
    if (err) *err = std::string("fcntl O_NONBLOCK failed: ") + std::strerror(errno);
    return false;
  }
  return true;
}

int RawSocketCapture::recv_packet(uint8_t* buf, size_t buf_size, std::string* err) {
  if (fd_ < 0) {
    if (err) *err = "socket not open";
    return -1;
  }

  ssize_t n = ::recv(fd_, buf, buf_size, 0);
  if (n > 0) return static_cast<int>(n);
  if (n == 0) return 0;

  // EAGAIN/EWOULDBLOCK means no data in non-blocking mode.
  if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;

  if (err) *err = std::string("recv failed: ") + std::strerror(errno);
  return -1;
}

void RawSocketCapture::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

bool RawSocketCapture::is_open() const { return fd_ >= 0; }

} // namespace modemprobe

#else
// ─────────────── Stub implementation (non-Linux or disabled) ────────────────

namespace modemprobe {

RawSocketCapture::~RawSocketCapture() {}

bool RawSocketCapture::open(const std::string& /*iface*/, std::string* err) {
  if (err) *err = "raw socket support not compiled (use -DMODEMPROBE_ENABLE_RAW_SOCKET=ON)";
  return false;
}

bool RawSocketCapture::set_nonblocking(std::string* err) {
  if (err) *err = "raw socket not available";
  return false;
}

int RawSocketCapture::recv_packet(uint8_t* /*buf*/, size_t /*buf_size*/, std::string* err) {
  if (err) *err = "raw socket not available";
  return -1;
}

void RawSocketCapture::close() {}
bool RawSocketCapture::is_open() const { return false; }

} // namespace modemprobe

#endif // MODEMPROBE_ENABLE_RAW_SOCKET
