#pragma once
// Configurable processing pipeline for different protocol stacks.
// Select which layers to enable at runtime via CLI flags.

#include <cstdint>

namespace modemprobe {

// Pipeline configuration: controls which processing stages are active.
// All enabled by default; disable specific stages to reduce overhead
// or focus analysis on particular protocol layers.
struct PipelineConfig {
  // Layer 2-4 parsing (always on for meaningful analysis)
  bool enable_ethernet = true;
  bool enable_ipv4 = true;
  bool enable_tcp = true;
  bool enable_udp = true;

  // Application-layer fingerprinting
  bool enable_http_fingerprint = true;
  bool enable_dns_fingerprint = true;
  bool enable_rtp_fingerprint = true;
  bool enable_sip_fingerprint = true;

  // Multimedia analysis
  bool enable_h264_detection = true;
  bool enable_rtp_stream_tracking = true;

  // Anomaly detection
  bool enable_anomaly_detection = true;
  bool enable_tcp_seq_tracking = true;

  // Wireless simulation injection (off by default; demo feature)
  bool enable_wifi_sim = false;
  bool enable_lte_sim = false;

  // Ring buffer vs direct processing
  bool use_ring_buffer = true;

  // Convenience: enable all application fingerprinting
  void enable_all_fingerprinting() {
    enable_http_fingerprint = true;
    enable_dns_fingerprint = true;
    enable_rtp_fingerprint = true;
    enable_sip_fingerprint = true;
  }

  // Convenience: disable all application fingerprinting
  void disable_all_fingerprinting() {
    enable_http_fingerprint = false;
    enable_dns_fingerprint = false;
    enable_rtp_fingerprint = false;
    enable_sip_fingerprint = false;
  }

  // Minimal pipeline: only L2-L4 parsing, no fingerprinting or anomaly detection
  static PipelineConfig minimal() {
    PipelineConfig c;
    c.disable_all_fingerprinting();
    c.enable_h264_detection = false;
    c.enable_rtp_stream_tracking = false;
    c.enable_anomaly_detection = false;
    c.enable_tcp_seq_tracking = false;
    return c;
  }

  // Full pipeline: everything enabled (default)
  static PipelineConfig full() {
    return PipelineConfig{};
  }
};

} // namespace modemprobe
