#pragma once
// Lock-free Single-Producer Single-Consumer (SPSC) ring buffer.
// Embedded-style: pre-allocated fixed-size slots, zero heap allocation after init,
// bounded memory footprint. Uses std::atomic for thread-safe head/tail indices.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace modemprobe {

// Each slot holds a copied packet (up to kMaxPacketSize bytes).
// This avoids storing raw pointers to libpcap's internal buffers.
struct RingSlot {
  static constexpr size_t kMaxPacketSize = 2048; // enough for most Ethernet frames
  uint8_t data[kMaxPacketSize];
  uint32_t caplen = 0;
  uint64_t ts_us = 0;
  bool occupied = false;
};

// SPSC ring buffer with power-of-two capacity for fast modulo via bitmask.
// - Producer calls try_push() from capture thread/loop.
// - Consumer calls try_pop() from processing thread/loop.
// - In single-threaded mode, push then pop-all each iteration still works and
//   demonstrates the architecture for resume/interview purposes.
template <uint32_t CapacityLog2 = 10> // default 1024 slots
class SpscRingBuffer {
public:
  static constexpr uint32_t kCapacity = 1u << CapacityLog2;
  static constexpr uint32_t kMask = kCapacity - 1;

  SpscRingBuffer() : head_(0), tail_(0), drops_(0) {}

  // Producer: copy packet data into next free slot. Returns false if full (drop).
  bool try_push(const uint8_t* pkt_data, uint32_t caplen, uint64_t ts_us) {
    const uint32_t head = head_.load(std::memory_order_relaxed);
    const uint32_t next = (head + 1) & kMask;

    // Full if next write position == current read position.
    if (next == tail_.load(std::memory_order_acquire)) {
      drops_.fetch_add(1, std::memory_order_relaxed);
      return false;
    }

    RingSlot& slot = slots_[head];
    const uint32_t copy_len = (caplen <= RingSlot::kMaxPacketSize)
                                  ? caplen
                                  : static_cast<uint32_t>(RingSlot::kMaxPacketSize);
    std::memcpy(slot.data, pkt_data, copy_len);
    slot.caplen = copy_len;
    slot.ts_us = ts_us;

    head_.store(next, std::memory_order_release);
    return true;
  }

  // Consumer: read next available packet. Returns false if empty.
  bool try_pop(const uint8_t*& out_data, uint32_t& out_caplen, uint64_t& out_ts_us) {
    const uint32_t tail = tail_.load(std::memory_order_relaxed);

    // Empty if read position == write position.
    if (tail == head_.load(std::memory_order_acquire)) {
      return false;
    }

    const RingSlot& slot = slots_[tail];
    out_data = slot.data;
    out_caplen = slot.caplen;
    out_ts_us = slot.ts_us;

    tail_.store((tail + 1) & kMask, std::memory_order_release);
    return true;
  }

  uint32_t capacity() const { return kCapacity; }

  uint32_t size() const {
    const uint32_t h = head_.load(std::memory_order_relaxed);
    const uint32_t t = tail_.load(std::memory_order_relaxed);
    return (h - t) & kMask;
  }

  uint64_t drops() const { return drops_.load(std::memory_order_relaxed); }

  // Total pre-allocated memory: kCapacity * sizeof(RingSlot).
  // With default 1024 slots * ~2064 bytes = ~2 MB. Well under 8 MB.
  static constexpr size_t memory_footprint() {
    return kCapacity * sizeof(RingSlot);
  }

private:
  // Separate cache lines to avoid false sharing between producer and consumer.
  alignas(64) std::atomic<uint32_t> head_;
  alignas(64) std::atomic<uint32_t> tail_;
  std::atomic<uint64_t> drops_;

  RingSlot slots_[kCapacity];
};

// Default ring buffer type: 1024 slots, ~2 MB footprint.
using PacketRingBuffer = SpscRingBuffer<10>;

} // namespace modemprobe
