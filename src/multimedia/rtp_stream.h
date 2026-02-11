#ifndef RTP_STREAM_H
#define RTP_STREAM_H

#include <cstdint>
#include <unordered_map>
#include <vector>
#include "common.h"
#include "fingerprinting/rtp.h"

// RTP stream information
struct RTPStream {
    uint32_t ssrc;
    uint16_t last_sequence;
    uint32_t packet_count;
    uint32_t lost_packets;
    uint64_t first_timestamp;
    uint64_t last_timestamp;
    bool sequence_initialized;  // Track if we've seen the first packet
    
    RTPStream() 
        : ssrc(0), last_sequence(0), packet_count(0), 
          lost_packets(0), first_timestamp(0), last_timestamp(0),
          sequence_initialized(false) {}
};

class RTPStreamAnalyzer {
private:
    std::unordered_map<uint32_t, RTPStream> streams_;
    
public:
    // Process an RTP packet and update stream statistics
    bool process_rtp_packet(const uint8_t* payload, size_t payload_len, uint64_t timestamp) {
        if (payload_len < 12) {
            return false;
        }
        
        RTPHeader rtp;
        if (!rtp.parse(payload, payload_len)) {
            return false;
        }
        
        uint32_t ssrc = rtp.get_ssrc();
        uint16_t seq = rtp.get_sequence_number();
        
        // Find or create stream
        auto it = streams_.find(ssrc);
        if (it == streams_.end()) {
            RTPStream stream;
            stream.ssrc = ssrc;
            stream.last_sequence = seq;
            stream.packet_count = 1;
            stream.first_timestamp = timestamp;
            stream.last_timestamp = timestamp;
            stream.sequence_initialized = true;
            streams_[ssrc] = stream;
        } else {
            RTPStream& stream = it->second;
            stream.packet_count++;
            stream.last_timestamp = timestamp;
            
            // Fix Bug 4: Properly handle sequence number wrap-around and out-of-order packets
            if (stream.sequence_initialized) {
                uint16_t last_seq = stream.last_sequence;
                uint16_t expected_seq = (last_seq == 65535) ? 0 : (last_seq + 1);
                
                if (seq == expected_seq) {
                    // Perfect sequence, no gap
                    stream.last_sequence = seq;
                } else if (seq == last_seq) {
                    // Duplicate packet - ignore
                } else if (seq > last_seq) {
                    // Sequence increased, but not by 1 - gap detected
                    // Check if this could be wrap-around (unlikely but possible)
                    // Normal case: gap = seq - last_seq - 1
                    uint16_t gap = seq - last_seq - 1;
                    if (gap < 1000) {  // Reasonable gap threshold
                        stream.lost_packets += gap;
                    }
                    stream.last_sequence = seq;
                } else {
                    // seq < last_seq - could be wrap-around or out-of-order
                    // Check if it's wrap-around: last_seq is large and seq is small
                    if (last_seq > 60000 && seq < 1000) {
                        // Wrap-around: sequence wrapped from 65535 to 0
                        // Calculate gap: from (last_seq + 1) to 65535, then 0 to seq
                        // Total sequence numbers = (65535 - last_seq) + (seq + 1)
                        // Lost = total - 1 (the one we received)
                        uint16_t total_seq = (65535 - last_seq) + (seq + 1);
                        if (total_seq > 0 && total_seq < 1000) {  // Reasonable gap after wrap
                            stream.lost_packets += (total_seq - 1);
                        }
                        stream.last_sequence = seq;
                    } else {
                        // Out-of-order packet - don't update sequence or count as lost
                        // Just ignore for now (could track out-of-order separately)
                    }
                }
            } else {
                // First packet in stream
                stream.last_sequence = seq;
                stream.sequence_initialized = true;
            }
        }
        
        return true;
    }
    
    // Get all streams
    const std::unordered_map<uint32_t, RTPStream>& get_streams() const {
        return streams_;
    }
    
    // Get stream count
    size_t get_stream_count() const {
        return streams_.size();
    }
    
    // Get total lost packets across all streams
    uint32_t get_total_lost_packets() const {
        uint32_t total = 0;
        for (const auto& pair : streams_) {
            total += pair.second.lost_packets;
        }
        return total;
    }
    
    // Clear all streams
    void clear() {
        streams_.clear();
    }
};

#endif // RTP_STREAM_H

