#include "core/packet_ring.h"

#include <algorithm>
#include <cstring>

namespace modemprobe {

PacketRing::PacketRing() {
  // pre-fill free ring with all block handles
  for (uint32_t i = 0; i < kBlocks; ++i) {
    // free_ ring is SPSC; constructor runs single-threaded, so push always succeeds
    free_.push(i);
  }
}

bool PacketRing::alloc(uint32_t want_len, uint32_t& out_handle, uint8_t*& out_ptr) {
  if (want_len > kBlockSize) want_len = kBlockSize;
  uint32_t h = 0;
  if (!free_.pop(h)) {
    drops_no_free_.fetch_add(1);
    return false;
  }
  out_handle = h;
  out_ptr = blocks_[h].data();
  return true;
}

bool PacketRing::commit(uint32_t handle, uint32_t actual_len, uint64_t ts_us, uint32_t ifindex, PacketKind kind) {
  if (actual_len > kBlockSize) actual_len = kBlockSize;
  meta_[handle].len = actual_len;
  meta_[handle].ts_us = ts_us;
  meta_[handle].ifindex = ifindex;
  meta_[handle].kind = kind;

  if (!filled_.push(handle)) {
    drops_ring_full_.fetch_add(1);
    // return handle to free list so we don't leak pool blocks
    free_.push(handle);
    return false;
  }
  return true;
}

bool PacketRing::pop(PacketView& out_view) {
  uint32_t h = 0;
  if (!filled_.pop(h)) return false;
  const Meta& m = meta_[h];
  out_view.data = blocks_[h].data();
  out_view.len = m.len;
  out_view.ts_us = m.ts_us;
  out_view.ifindex = m.ifindex;
  out_view.kind = m.kind;
  out_view.handle = h;
  return true;
}

void PacketRing::release(uint32_t handle) {
  // Return block to free ring. If it fails, drop it (should not happen for sane sizes).
  free_.push(handle);
}

} // namespace modemprobe
