// ModemProbe – Baseband Protocol Analyzer & Packet Processor
// main.cpp: argument parsing, capture loop (ring buffer or direct), periodic
// console stats, wireless simulation injection, configurable pipeline, JSON report.

#include "anomaly.h"
#include "capture_pcap.h"
#include "fingerprint.h"
#include "parse.h"
#include "pipeline.h"
#include "raw_socket.h"
#include "report_json.h"
#include "ring_buffer.h"
#include "rtp_stream.h"
#include "wireless_sim.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unordered_map>

using namespace modemprobe;
using Clock = std::chrono::steady_clock;

// ─────────────────────────────── Usage ───────────────────────────────────────

static void usage(const char* prog) {
  std::fprintf(stderr,
    "ModemProbe – Baseband Protocol Analyzer & Packet Processor\n\n"
    "Usage:\n"
    "  %s --pcap <file.pcap> [options]\n"
    "  %s --iface <eth0|lo|wlan0> [--seconds <N>] [options]\n"
    "  %s --demo [options]\n\n"
    "Capture options:\n"
    "  --pcap <file>          Read packets from a .pcap file (no sudo needed)\n"
    "  --iface <name>         Live capture on interface (needs sudo)\n"
    "  --seconds <N>          Duration for live capture (default: 10)\n"
    "  --backend <pcap|raw>   Capture backend: pcap (default) or raw (AF_PACKET)\n\n"
    "Simulation options:\n"
    "  --demo                 Run WiFi/LTE simulation demo (no network needed)\n"
    "  --inject-wifi          Also inject WiFi 802.11 beacons during capture\n"
    "  --inject-lte           Also inject LTE PDSCH/PUSCH frames during capture\n\n"
    "Pipeline options:\n"
    "  --pipeline <full|minimal>  Processing pipeline (default: full)\n"
    "  --no-ring-buffer       Disable ring buffer (direct processing)\n\n"
    "Output:\n"
    "  --report <file>        JSON report path (default: report.json)\n"
    "  --list-devices         List available interfaces and exit\n"
    "  -h, --help             Show this help\n",
    prog, prog, prog);
}

static const char* proto_name(AppProto p) {
  switch (p) {
    case AppProto::HTTP: return "HTTP";
    case AppProto::DNS:  return "DNS";
    case AppProto::RTP:  return "RTP";
    case AppProto::SIP:  return "SIP";
    default:             return nullptr;
  }
}

// ───────────────────────── Packet processing core ────────────────────────────

struct Stats {
  uint64_t packets = 0;
  uint64_t bytes = 0;
  double parse_time_us_sum = 0.0;
  std::unordered_map<std::string, uint64_t> proto_counts;
  uint64_t h264_nal_detections = 0;
  uint64_t wifi_beacons = 0;
  uint64_t lte_frames = 0;
  uint64_t ring_drops = 0;
};

static void process_one(const uint8_t* data, size_t caplen, uint64_t ts_us,
                        Stats& stats, AnomalyCollector& anomalies,
                        RtpStreamTracker& rtp_tracker, const PipelineConfig& cfg) {
  stats.packets++;
  stats.bytes += caplen;

  anomalies.set_current_ts(ts_us);
  ParseAnomalies pa;
  if (cfg.enable_anomaly_detection) {
    pa.add = AnomalyCollector::parse_add;
    pa.user = &anomalies;
  }

  auto t0 = Clock::now();

  ParsedPacket pkt;
  parse_ethernet_ipv4_tcpudp(data, caplen, pkt,
                             cfg.enable_anomaly_detection ? &pa : nullptr);

  if (pkt.has_eth) stats.proto_counts["Ethernet"]++;
  if (pkt.has_ip4) stats.proto_counts["IPv4"]++;
  if (pkt.has_tcp) {
    stats.proto_counts["TCP"]++;
    if (cfg.enable_tcp_seq_tracking) anomalies.on_tcp_packet(pkt, ts_us);
  }
  if (pkt.has_udp) stats.proto_counts["UDP"]++;

  // Detect simulated wireless frames inside UDP payload.
  if (pkt.has_udp && pkt.l4_payload && pkt.l4_payload_len > 0) {
    if (is_simulated_wifi_beacon(pkt.l4_payload, pkt.l4_payload_len)) {
      stats.wifi_beacons++;
      stats.proto_counts["WiFi_Beacon"]++;
    }
    LteDirection lte_dir;
    if (is_simulated_lte_frame(pkt.l4_payload, pkt.l4_payload_len, &lte_dir)) {
      stats.lte_frames++;
      stats.proto_counts[lte_dir == LteDirection::Downlink ? "LTE_PDSCH" : "LTE_PUSCH"]++;
    }
  }

  // Application-layer fingerprinting.
  FingerprintResult fp;
  if (cfg.enable_http_fingerprint || cfg.enable_dns_fingerprint ||
      cfg.enable_rtp_fingerprint || cfg.enable_sip_fingerprint) {
    fp = fingerprint_app(pkt);
    const char* name = proto_name(fp.proto);
    if (name) stats.proto_counts[name]++;
  }

  // RTP stream tracking + H.264 detection.
  if (cfg.enable_rtp_stream_tracking &&
      fp.proto == AppProto::RTP && pkt.l4_payload && pkt.l4_payload_len >= 12) {
    rtp_tracker.on_rtp_packet(pkt.l4_payload, pkt.l4_payload_len, ts_us,
                              cfg.enable_h264_detection && fp.h264_nal_start);
    if (cfg.enable_h264_detection && fp.h264_nal_start) {
      stats.h264_nal_detections++;
      stats.proto_counts["H264_NAL"]++;
    }
  }

  auto t1 = Clock::now();
  stats.parse_time_us_sum +=
      std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
}

// ──────────────────────── Periodic console stats ─────────────────────────────

static void print_stats(const Stats& s, double elapsed_s,
                        const AnomalyCollector& a, const RtpStreamTracker& r) {
  double pps = (elapsed_s > 0) ? static_cast<double>(s.packets) / elapsed_s : 0;
  double avg = (s.packets > 0) ? s.parse_time_us_sum / static_cast<double>(s.packets) : 0;

  std::printf("\n--- ModemProbe stats (%.1fs) ---\n", elapsed_s);
  std::printf("Packets: %llu | Bytes: %llu | pps: %.1f | avg_parse: %.1f us\n",
              (unsigned long long)s.packets, (unsigned long long)s.bytes, pps, avg);

  std::printf("Protocols:");
  for (const auto& kv : s.proto_counts)
    std::printf("  %s=%llu", kv.first.c_str(), (unsigned long long)kv.second);
  std::printf("\n");

  if (s.wifi_beacons || s.lte_frames)
    std::printf("Wireless sim: WiFi=%llu LTE=%llu\n",
                (unsigned long long)s.wifi_beacons, (unsigned long long)s.lte_frames);
  if (s.ring_drops)
    std::printf("Ring drops: %llu\n", (unsigned long long)s.ring_drops);

  if (!a.counts().empty()) {
    std::printf("Anomalies:");
    for (const auto& kv : a.counts())
      std::printf("  %s=%llu", kv.first.c_str(), (unsigned long long)kv.second);
    std::printf("\n");
  }

  if (!r.streams().empty()) {
    std::printf("RTP streams: %zu\n", r.streams().size());
    for (const auto& kv : r.streams()) {
      const auto& st = kv.second;
      std::printf("  SSRC=0x%08X rcv=%u lost=%u dup=%u ooo=%u h264=%s\n",
                  st.ssrc, st.received_unique, st.estimated_lost,
                  st.duplicates, st.out_of_order, st.saw_h264 ? "yes" : "no");
    }
  }
}

// ───────────────────────── Build JSON report ─────────────────────────────────

static ReportData build_report(const Stats& s, double elapsed_s,
                               const AnomalyCollector& a, const RtpStreamTracker& r) {
  ReportData rpt;
  rpt.protocol_counts = s.proto_counts;
  rpt.anomaly_counts = a.counts();
  rpt.anomaly_events_stored = a.events().size();
  rpt.anomaly_events_dropped = a.dropped_events();
  rpt.packets_total = s.packets;
  rpt.elapsed_seconds = elapsed_s;
  rpt.pps = (elapsed_s > 0) ? static_cast<double>(s.packets) / elapsed_s : 0;
  rpt.avg_parse_us = (s.packets > 0)
      ? s.parse_time_us_sum / static_cast<double>(s.packets) : 0;

  for (const auto& kv : r.streams()) {
    const auto& st = kv.second;
    RtpStreamSummary sum;
    sum.ssrc = st.ssrc;
    sum.received_unique = st.received_unique;
    sum.duplicates = st.duplicates;
    sum.out_of_order = st.out_of_order;
    sum.too_old = st.too_old;
    sum.estimated_lost = st.estimated_lost;
    sum.first_ts_us = st.first_ts_us;
    sum.last_ts_us = st.last_ts_us;
    sum.saw_h264 = st.saw_h264;
    rpt.rtp_streams.push_back(sum);
  }
  return rpt;
}

// ──────────── WiFi/LTE simulation injection into ring buffer ─────────────────

static void inject_sim(PacketRingBuffer& ring, const PipelineConfig& cfg,
                       uint32_t& wifi_seq, uint32_t& lte_frame) {
  auto now_us = static_cast<uint64_t>(
      std::chrono::duration_cast<std::chrono::microseconds>(
          Clock::now().time_since_epoch()).count());

  if (cfg.enable_wifi_sim) {
    WifiBeaconParams bp;
    auto pkt = generate_wifi_beacon(bp, wifi_seq++);
    ring.try_push(pkt.data(), static_cast<uint32_t>(pkt.size()), now_us);
  }
  if (cfg.enable_lte_sim) {
    LteFrameParams dl; dl.direction = LteDirection::Downlink;
    dl.subframe = static_cast<uint8_t>(lte_frame % 10);
    auto dp = generate_lte_frame(dl, lte_frame);
    ring.try_push(dp.data(), static_cast<uint32_t>(dp.size()), now_us);

    LteFrameParams ul; ul.direction = LteDirection::Uplink;
    ul.subframe = static_cast<uint8_t>(lte_frame % 10);
    auto up = generate_lte_frame(ul, lte_frame);
    ring.try_push(up.data(), static_cast<uint32_t>(up.size()), now_us);
    lte_frame++;
  }
}

static void drain_ring(PacketRingBuffer& ring, Stats& stats,
                       AnomalyCollector& anomalies, RtpStreamTracker& rtp,
                       const PipelineConfig& cfg) {
  const uint8_t* d; uint32_t len; uint64_t ts;
  while (ring.try_pop(d, len, ts))
    process_one(d, len, ts, stats, anomalies, rtp, cfg);
  stats.ring_drops = ring.drops();
}

// ────────────────────────── Demo mode ────────────────────────────────────────

static int run_demo(const std::string& report_path, PipelineConfig cfg) {
  std::printf("========================================\n"
              " ModemProbe – Simulation Demo\n"
              "========================================\n");

  PacketRingBuffer ring;
  Stats stats;
  AnomalyCollector anomalies;
  RtpStreamTracker rtp;
  cfg.enable_wifi_sim = true;
  cfg.enable_lte_sim = true;

  auto t0 = Clock::now();

  // Generate batches of WiFi beacons and LTE frames.
  std::printf("\n--- WiFi 802.11 Beacon Simulation ---\n");
  for (uint32_t i = 0; i < 8; i++) {
    WifiBeaconParams bp;
    bp.channel = static_cast<uint8_t>(1 + (i % 11));
    char ssid[32]; std::snprintf(ssid, sizeof(ssid), "ModemProbe_AP%u", i);
    bp.ssid = ssid;
    bp.bssid[5] = static_cast<uint8_t>(i);
    auto pkt = generate_wifi_beacon(bp, i);
    auto now_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now().time_since_epoch()).count());
    ring.try_push(pkt.data(), static_cast<uint32_t>(pkt.size()), now_us);
    std::printf("  Beacon %u: SSID=\"%s\" CH=%u\n", i, ssid, bp.channel);
  }
  drain_ring(ring, stats, anomalies, rtp, cfg);

  std::printf("\n--- LTE PDSCH (Downlink) Simulation ---\n");
  for (uint32_t sf = 0; sf < 10; sf++) {
    LteFrameParams dl;
    dl.direction = LteDirection::Downlink;
    dl.subframe = static_cast<uint8_t>(sf);
    dl.rnti = 0x1234;
    dl.mcs = static_cast<uint8_t>(10 + (sf % 5));
    dl.num_prb = 50;
    auto pkt = generate_lte_frame(dl, sf);
    auto now_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now().time_since_epoch()).count());
    ring.try_push(pkt.data(), static_cast<uint32_t>(pkt.size()), now_us);
    std::printf("  SF%u: MCS=%u PRB=%u RNTI=0x%04X\n", sf, dl.mcs, dl.num_prb, dl.rnti);
  }
  drain_ring(ring, stats, anomalies, rtp, cfg);

  std::printf("\n--- LTE PUSCH (Uplink) Simulation ---\n");
  for (uint32_t sf = 0; sf < 10; sf++) {
    LteFrameParams ul;
    ul.direction = LteDirection::Uplink;
    ul.subframe = static_cast<uint8_t>(sf);
    ul.rnti = 0x5678;
    ul.mcs = static_cast<uint8_t>(8 + (sf % 4));
    ul.num_prb = 25;
    auto pkt = generate_lte_frame(ul, sf);
    auto now_us = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now().time_since_epoch()).count());
    ring.try_push(pkt.data(), static_cast<uint32_t>(pkt.size()), now_us);
  }
  drain_ring(ring, stats, anomalies, rtp, cfg);
  std::printf("  Generated 10 PUSCH subframes (RNTI=0x5678)\n");

  auto t1 = Clock::now();
  double elapsed = std::chrono::duration<double>(t1 - t0).count();
  print_stats(stats, elapsed, anomalies, rtp);

  std::string err;
  auto rpt = build_report(stats, elapsed, anomalies, rtp);
  if (!write_report_json(report_path, rpt, &err))
    std::fprintf(stderr, "Error writing report: %s\n", err.c_str());
  else
    std::printf("\nJSON report: %s\n", report_path.c_str());

  // Show available capture backends.
  std::printf("\n--- Available capture backends ---\n");
  auto devs = PcapHandle::list_devices(&err);
  std::printf("  libpcap devices:");
  if (devs.empty()) std::printf(" (none%s)", err.empty() ? "" : (": " + err).c_str());
  else for (const auto& d : devs) std::printf(" %s", d.c_str());
  std::printf("\n  Raw socket: %s\n",
#ifdef MODEMPROBE_ENABLE_RAW_SOCKET
    "available (compile flag ON)"
#else
    "not compiled (use -DMODEMPROBE_ENABLE_RAW_SOCKET=ON)"
#endif
  );

  return 0;
}

// ────────────────────────── Offline pcap mode ────────────────────────────────

static int run_offline(const std::string& pcap_path, const std::string& report_path,
                       const PipelineConfig& cfg) {
  PcapHandle pcap;
  std::string err;
  if (!pcap.open_offline(pcap_path, &err)) {
    std::fprintf(stderr, "Error: %s\n", err.c_str());
    return 1;
  }

  Stats stats; AnomalyCollector anomalies; RtpStreamTracker rtp;
  PacketRingBuffer ring;
  uint32_t wifi_seq = 0, lte_frame = 0, sim_ctr = 0;

  auto t0 = Clock::now();
  auto t_print = t0;
  const pcap_pkthdr* hdr; const uint8_t* data;

  while (true) {
    int rc = pcap.next(&hdr, &data);
    if (rc == -2) break;
    if (rc == -1) { std::fprintf(stderr, "pcap error: %s\n", pcap.last_error().c_str()); break; }
    if (rc == 0) continue;

    uint64_t ts = static_cast<uint64_t>(hdr->ts.tv_sec)*1000000ULL + hdr->ts.tv_usec;

    if (cfg.use_ring_buffer) {
      ring.try_push(data, hdr->caplen, ts);
      if ((cfg.enable_wifi_sim || cfg.enable_lte_sim) && (++sim_ctr % 100 == 0))
        inject_sim(ring, cfg, wifi_seq, lte_frame);
      drain_ring(ring, stats, anomalies, rtp, cfg);
    } else {
      process_one(data, hdr->caplen, ts, stats, anomalies, rtp, cfg);
    }

    auto now = Clock::now();
    if (std::chrono::duration<double>(now - t_print).count() >= 2.0) {
      print_stats(stats, std::chrono::duration<double>(now - t0).count(), anomalies, rtp);
      t_print = now;
    }
  }

  double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
  print_stats(stats, elapsed, anomalies, rtp);

  auto rpt = build_report(stats, elapsed, anomalies, rtp);
  if (!write_report_json(report_path, rpt, &err))
    std::fprintf(stderr, "Error: %s\n", err.c_str());
  else
    std::printf("\nJSON report: %s\n", report_path.c_str());
  return 0;
}

// ──────────────────────── Live pcap capture mode ─────────────────────────────

static int run_live_pcap(const std::string& iface, int seconds,
                         const std::string& report_path, const PipelineConfig& cfg) {
  PcapHandle pcap; std::string err;
  if (!pcap.open_live_nonblocking(iface, 65535, true, 1, &err)) {
    std::fprintf(stderr, "Error: %s\n", err.c_str());
    return 1;
  }
  std::printf("Capturing on %s for %d seconds (libpcap, non-blocking)...\n", iface.c_str(), seconds);

  Stats stats; AnomalyCollector anomalies; RtpStreamTracker rtp;
  PacketRingBuffer ring;
  uint32_t wifi_seq = 0, lte_frame = 0, sim_ctr = 0;

  auto t0 = Clock::now(); auto t_print = t0;
  double duration = static_cast<double>(seconds);

  while (true) {
    auto now = Clock::now();
    double elapsed = std::chrono::duration<double>(now - t0).count();
    if (elapsed >= duration) break;

    const pcap_pkthdr* hdr; const uint8_t* data;
    int rc = pcap.next(&hdr, &data);
    if (rc == 1) {
      uint64_t ts = static_cast<uint64_t>(hdr->ts.tv_sec)*1000000ULL + hdr->ts.tv_usec;
      if (cfg.use_ring_buffer) {
        ring.try_push(data, hdr->caplen, ts);
        if ((cfg.enable_wifi_sim || cfg.enable_lte_sim) && (++sim_ctr % 50 == 0))
          inject_sim(ring, cfg, wifi_seq, lte_frame);
        drain_ring(ring, stats, anomalies, rtp, cfg);
      } else {
        process_one(data, hdr->caplen, ts, stats, anomalies, rtp, cfg);
      }
    } else if (rc == -1) {
      std::fprintf(stderr, "pcap error: %s\n", pcap.last_error().c_str()); break;
    }

    if (std::chrono::duration<double>(now - t_print).count() >= 2.0) {
      print_stats(stats, elapsed, anomalies, rtp);
      t_print = now;
    }
  }

  double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
  print_stats(stats, elapsed, anomalies, rtp);

  auto rpt = build_report(stats, elapsed, anomalies, rtp);
  if (!write_report_json(report_path, rpt, &err))
    std::fprintf(stderr, "Error: %s\n", err.c_str());
  else
    std::printf("\nJSON report: %s\n", report_path.c_str());
  return 0;
}

// ──────────────────── Live raw socket capture mode ───────────────────────────

static int run_live_raw(const std::string& iface, int seconds,
                        const std::string& report_path, const PipelineConfig& cfg) {
  RawSocketCapture raw; std::string err;
  if (!raw.open(iface, &err)) { std::fprintf(stderr, "Error: %s\n", err.c_str()); return 1; }
  if (!raw.set_nonblocking(&err)) { std::fprintf(stderr, "Error: %s\n", err.c_str()); return 1; }
  std::printf("Capturing on %s for %d seconds (AF_PACKET raw socket)...\n", iface.c_str(), seconds);

  Stats stats; AnomalyCollector anomalies; RtpStreamTracker rtp;
  PacketRingBuffer ring;
  uint32_t wifi_seq = 0, lte_frame = 0, sim_ctr = 0;
  uint8_t buf[RingSlot::kMaxPacketSize];

  auto t0 = Clock::now(); auto t_print = t0;
  double duration = static_cast<double>(seconds);

  while (true) {
    auto now = Clock::now();
    double elapsed = std::chrono::duration<double>(now - t0).count();
    if (elapsed >= duration) break;

    int n = raw.recv_packet(buf, sizeof(buf), &err);
    if (n > 0) {
      auto ts = static_cast<uint64_t>(
          std::chrono::duration_cast<std::chrono::microseconds>(
              now.time_since_epoch()).count());
      if (cfg.use_ring_buffer) {
        ring.try_push(buf, static_cast<uint32_t>(n), ts);
        if ((cfg.enable_wifi_sim || cfg.enable_lte_sim) && (++sim_ctr % 50 == 0))
          inject_sim(ring, cfg, wifi_seq, lte_frame);
        drain_ring(ring, stats, anomalies, rtp, cfg);
      } else {
        process_one(buf, static_cast<size_t>(n), ts, stats, anomalies, rtp, cfg);
      }
    } else if (n == -1) {
      std::fprintf(stderr, "raw socket error: %s\n", err.c_str()); break;
    }

    if (std::chrono::duration<double>(now - t_print).count() >= 2.0) {
      print_stats(stats, elapsed, anomalies, rtp);
      t_print = now;
    }
  }

  double elapsed = std::chrono::duration<double>(Clock::now() - t0).count();
  print_stats(stats, elapsed, anomalies, rtp);

  auto rpt = build_report(stats, elapsed, anomalies, rtp);
  if (!write_report_json(report_path, rpt, &err))
    std::fprintf(stderr, "Error: %s\n", err.c_str());
  else
    std::printf("\nJSON report: %s\n", report_path.c_str());
  return 0;
}

// ──────────────────────────────── main ───────────────────────────────────────

int main(int argc, char* argv[]) {
  std::string pcap_file, iface, report_path = "report.json", backend = "pcap";
  int seconds = 10;
  bool list_devs = false, demo = false;
  PipelineConfig cfg = PipelineConfig::full();

  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    if      (a == "--pcap"    && i+1 < argc) pcap_file = argv[++i];
    else if (a == "--iface"   && i+1 < argc) iface = argv[++i];
    else if (a == "--seconds" && i+1 < argc) { seconds = std::atoi(argv[++i]); if (seconds<=0) seconds=10; }
    else if (a == "--report"  && i+1 < argc) report_path = argv[++i];
    else if (a == "--backend" && i+1 < argc) backend = argv[++i];
    else if (a == "--demo")           demo = true;
    else if (a == "--inject-wifi")    cfg.enable_wifi_sim = true;
    else if (a == "--inject-lte")     cfg.enable_lte_sim = true;
    else if (a == "--no-ring-buffer") cfg.use_ring_buffer = false;
    else if (a == "--pipeline" && i+1 < argc) {
      std::string p = argv[++i];
      if (p == "minimal") cfg = PipelineConfig::minimal();
      else if (p != "full") { std::fprintf(stderr, "Unknown pipeline: %s\n", p.c_str()); return 1; }
    }
    else if (a == "--list-devices") list_devs = true;
    else if (a == "-h" || a == "--help") { usage(argv[0]); return 0; }
    else { std::fprintf(stderr, "Unknown option: %s\n", a.c_str()); usage(argv[0]); return 1; }
  }

  if (list_devs) {
    std::string err;
    auto devs = PcapHandle::list_devices(&err);
    if (devs.empty()) std::printf("No devices found. %s\n", err.c_str());
    else { std::printf("Interfaces:\n"); for (auto& d : devs) std::printf("  %s\n", d.c_str()); }
    return 0;
  }

  if (cfg.use_ring_buffer)
    std::printf("Ring buffer: %u slots, %.1f KB\n",
                PacketRingBuffer::kCapacity,
                static_cast<double>(PacketRingBuffer::memory_footprint()) / 1024.0);

  // Default to demo when nothing specified.
  if (pcap_file.empty() && iface.empty() && !demo) {
    std::printf("No capture source – running demo. Use --help for options.\n\n");
    demo = true;
  }

  if (demo) return run_demo(report_path, cfg);
  if (!pcap_file.empty()) return run_offline(pcap_file, report_path, cfg);
  if (backend == "raw") return run_live_raw(iface, seconds, report_path, cfg);
  return run_live_pcap(iface, seconds, report_path, cfg);
}
