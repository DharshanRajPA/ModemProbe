#include "capture_pcap.h"

#include <cstring>

namespace modemprobe {

PcapHandle::~PcapHandle() { close(); }

PcapHandle::PcapHandle(PcapHandle&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

PcapHandle& PcapHandle::operator=(PcapHandle&& other) noexcept {
  if (this == &other) return *this;
  close();
  handle_ = other.handle_;
  other.handle_ = nullptr;
  return *this;
}

bool PcapHandle::open_live_nonblocking(const std::string& iface,
                                       int snaplen,
                                       bool promiscuous,
                                       int read_timeout_ms,
                                       std::string* err) {
  close();

  char errbuf[PCAP_ERRBUF_SIZE];
  std::memset(errbuf, 0, sizeof(errbuf));

  handle_ = pcap_open_live(iface.c_str(), snaplen, promiscuous ? 1 : 0, read_timeout_ms, errbuf);
  if (!handle_) {
    if (err) *err = std::string("pcap_open_live failed: ") + errbuf;
    return false;
  }

  // Non-blocking: pcap_next_ex will return 0 when no packet is ready.
  if (pcap_setnonblock(handle_, 1, errbuf) == -1) {
    if (err) *err = std::string("pcap_setnonblock failed: ") + errbuf;
    close();
    return false;
  }

  return true;
}

bool PcapHandle::open_offline(const std::string& pcap_path, std::string* err) {
  close();

  char errbuf[PCAP_ERRBUF_SIZE];
  std::memset(errbuf, 0, sizeof(errbuf));

  handle_ = pcap_open_offline(pcap_path.c_str(), errbuf);
  if (!handle_) {
    if (err) *err = std::string("pcap_open_offline failed: ") + errbuf;
    return false;
  }

  return true;
}

void PcapHandle::close() {
  if (handle_) {
    pcap_close(handle_);
    handle_ = nullptr;
  }
}

int PcapHandle::next(const pcap_pkthdr** hdr, const uint8_t** data) {
  if (!handle_) return -1;

  const u_char* pkt = nullptr;
  pcap_pkthdr* h = nullptr;
  int rc = pcap_next_ex(handle_, &h, &pkt);
  if (rc == 1) {
    *hdr = h;
    *data = reinterpret_cast<const uint8_t*>(pkt);
  }
  return rc;
}

std::string PcapHandle::last_error() const {
  if (!handle_) return "pcap handle not open";
  const char* e = pcap_geterr(handle_);
  return e ? std::string(e) : std::string();
}

std::vector<std::string> PcapHandle::list_devices(std::string* err) {
  std::vector<std::string> out;
  char errbuf[PCAP_ERRBUF_SIZE];
  std::memset(errbuf, 0, sizeof(errbuf));

  pcap_if_t* alldevs = nullptr;
  if (pcap_findalldevs(&alldevs, errbuf) == -1) {
    if (err) *err = std::string("pcap_findalldevs failed: ") + errbuf;
    return out;
  }

  for (pcap_if_t* d = alldevs; d; d = d->next) {
    if (d->name) out.emplace_back(d->name);
  }
  pcap_freealldevs(alldevs);
  return out;
}

} // namespace modemprobe

