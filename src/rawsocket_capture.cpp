#include "rawsocket_capture.h"

#ifdef MODEMPROBE_ENABLE_RAW_SOCKET

#include <cerrno>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <fcntl.h>
#include <ifaddrs.h>

namespace modemprobe {

RawSocketCapture::~RawSocketCapture() { close(); }

bool RawSocketCapture::open(const std::string& iface, std::string* err) {
  close();

  // Create raw socket: AF_PACKET gives us L2 frames including Ethernet header.
  fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd_ < 0) {
    last_err_ = std::string("socket(AF_PACKET) failed: ") + std::strerror(errno);
    if (err) *err = last_err_;
    return false;
  }

  // Resolve interface index.
  struct ifreq ifr;
  std::memset(&ifr, 0, sizeof(ifr));
  std::strncpy(ifr.ifr_name, iface.c_str(), IFNAMSIZ - 1);
  if (ioctl(fd_, SIOCGIFINDEX, &ifr) < 0) {
    last_err_ = std::string("ioctl(SIOCGIFINDEX) failed for '") + iface + "': " + std::strerror(errno);
    if (err) *err = last_err_;
    close();
    return false;
  }

  // Bind to the specific interface.
  struct sockaddr_ll sll;
  std::memset(&sll, 0, sizeof(sll));
  sll.sll_family   = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex  = ifr.ifr_ifindex;
  if (bind(fd_, reinterpret_cast<struct sockaddr*>(&sll), sizeof(sll)) < 0) {
    last_err_ = std::string("bind(AF_PACKET) failed: ") + std::strerror(errno);
    if (err) *err = last_err_;
    close();
    return false;
  }

  // Set non-blocking I/O (embedded-style: never block the processing thread).
  int flags = fcntl(fd_, F_GETFL, 0);
  if (flags >= 0) fcntl(fd_, F_SETFL, flags | O_NONBLOCK);

  // Enable promiscuous mode on the interface.
  struct packet_mreq mreq;
  std::memset(&mreq, 0, sizeof(mreq));
  mreq.mr_ifindex = ifr.ifr_ifindex;
  mreq.mr_type    = PACKET_MR_PROMISC;
  setsockopt(fd_, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

  return true;
}

void RawSocketCapture::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

int RawSocketCapture::recv_packet(uint8_t* buf, size_t buf_size) {
  if (fd_ < 0) return -1;
  ssize_t n = ::recv(fd_, buf, buf_size, 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) return 0; // non-blocking: no data
    last_err_ = std::string("recv failed: ") + std::strerror(errno);
    return -1;
  }
  return static_cast<int>(n);
}

std::vector<std::string> RawSocketCapture::list_interfaces(std::string* err) {
  std::vector<std::string> result;
  struct ifaddrs* ifaddr = nullptr;
  if (getifaddrs(&ifaddr) < 0) {
    if (err) *err = std::string("getifaddrs failed: ") + std::strerror(errno);
    return result;
  }
  for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
    if (!ifa->ifa_name) continue;
    std::string name(ifa->ifa_name);
    bool found = false;
    for (const auto& existing : result) {
      if (existing == name) { found = true; break; }
    }
    if (!found) result.push_back(name);
  }
  freeifaddrs(ifaddr);
  return result;
}

} // namespace modemprobe

#else // !MODEMPROBE_ENABLE_RAW_SOCKET

// Stub implementation when raw socket support is not compiled.
namespace modemprobe {

RawSocketCapture::~RawSocketCapture() {}

bool RawSocketCapture::open(const std::string&, std::string* err) {
  last_err_ = "Raw socket support not compiled (enable MODEMPROBE_ENABLE_RAW_SOCKET)";
  if (err) *err = last_err_;
  return false;
}

void RawSocketCapture::close() {}

int RawSocketCapture::recv_packet(uint8_t*, size_t) { return -1; }

std::vector<std::string> RawSocketCapture::list_interfaces(std::string* err) {
  if (err) *err = "Raw socket support not compiled";
  return {};
}

} // namespace modemprobe

#endif // MODEMPROBE_ENABLE_RAW_SOCKET
