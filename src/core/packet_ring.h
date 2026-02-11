#pragma once

#include <atomic>
#include <cstdint>
#include <cstddef>
#include <array>
#include "common.h"

// Fixed-size memory pool + SPSC rings:
// - producer: allocates a free block, copies packet bytes, commits handle into filled ring
// - consumer: pops handle from filled ring, processes PacketView, then releases handle back to free ring
//
// This keeps memory bounded (<8MB by default) and avoids storing pointers to libpcap buffers.

namespace modemprobe {

template <typename T, size_t N>
class SpscRing {
public:
  bool push(const T& v) {
    const size_t t = tail_.load(std::memory_order_relaxed);
    const size_t next = (t + 1) % N;
    if (next == head_.load(std::memory_order_acquire)) return false;
    buf_[t] = v;
    tail_.store(next, std::memory_order_release);
    return true;
  }

  bool pop(T& out) {
    const size_t h = head_.load(std::memory_order_relaxed);
    if (h == tail_.load(std::memory_order_acquire)) return false;
    out = buf_[h];
    head_.store((h + 1) % N, std::memory_order_release);
    return true;
  }

  size_t approx_size() const {
    const size_t h = head_.load(std::memory_order_acquire);
    const size_t t = tail_.load(std::memory_order_acquire);
    return (t >= h) ? (t - h) : (N - h + t);
  }

private:
  std::array<T, N> buf_{};
  std::atomic<size_t> head_{0};
  std::atomic<size_t> tail_{0};
};

struct PacketRingConfig {
  static constexpr uint32_t kDefaultBlockSize = 2048;
  static constexpr uint32_t kDefaultBlocks = 2048;   // 2048*2048 = 4MB
  static constexpr uint32_t kDefaultRing = 4096;     // ring holds handles
};

class PacketRing {
public:
  static constexpr uint32_t kBlockSize = PacketRingConfig::kDefaultBlockSize;
  static constexpr uint32_t kBlocks = PacketRingConfig::kDefaultBlocks;
  static constexpr uint32_t kRingN = PacketRingConfig::kDefaultRing;

  PacketRing();

  // Producer API
  bool alloc(uint32_t want_len, uint32_t& out_handle, uint8_t*& out_ptr);
  bool commit(uint32_t handle, uint32_t actual_len, uint64_t ts_us, uint32_t ifindex, PacketKind kind);

  // Consumer API
  bool pop(PacketView& out_view);
  void release(uint32_t handle);

  // Stats
  uint64_t drops_no_free() const { return drops_no_free_.load(); }
  uint64_t drops_ring_full() const { return drops_ring_full_.load(); }
  size_t filled_approx() const { return filled_.approx_size(); }

private:
  struct Meta {
    uint32_t len{0};
    uint64_t ts_us{0};
    uint32_t ifindex{0};
    PacketKind kind{PacketKind::Ethernet};
  };

  alignas(64) std::array<std::array<uint8_t, kBlockSize>, kBlocks> blocks_{};
  alignas(64) std::array<Meta, kBlocks> meta_{};

  // Handles are indices into blocks_/meta_
  SpscRing<uint32_t, kRingN> free_;
  SpscRing<uint32_t, kRingN> filled_;

  std::atomic<uint64_t> drops_no_free_{0};
  std::atomic<uint64_t> drops_ring_full_{0};
};

} // namespace modemprobe
