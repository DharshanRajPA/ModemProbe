#ifndef ANOMALY_H
#define ANOMALY_H

#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>
#include "common.h"
#include "protocols/protocol_parser.h"

struct Anomaly {
    enum Type {
        SEQUENCE_GAP,
        MALFORMED_HEADER,
        CHECKSUM_ERROR,
        UNEXPECTED_PROTOCOL,
        PAYLOAD_SIZE_MISMATCH
    };
    
    Type type;
    uint64_t timestamp_us;
    std::string description;
    ProtocolType protocol;
    
    Anomaly(Type t, uint64_t ts, const std::string& desc, ProtocolType proto = ProtocolType::UNKNOWN)
        : type(t), timestamp_us(ts), description(desc), protocol(proto) {}
};

class AnomalyDetector {
private:
    std::vector<Anomaly> anomalies_;
    // Fix Bug 5: Use unordered_map instead of fixed-size arrays to avoid stack overflow
    // This allows dynamic allocation and prevents 262KB stack allocation
    std::unordered_map<uint16_t, uint16_t> last_tcp_seq_;  // Track last sequence per port
    std::unordered_map<uint16_t, uint16_t> last_udp_seq_;  // Track last sequence per port
    
public:
    AnomalyDetector() = default;
    
    // Detect anomalies in a parsed packet
    void detect(const ParsedPacket& packet, uint64_t timestamp_us) {
        // Check for malformed headers
        if (packet.has_ip) {
            if (packet.ip.version() != 4) {
                anomalies_.emplace_back(Anomaly::UNEXPECTED_PROTOCOL, timestamp_us,
                                       "Non-IPv4 packet detected", ProtocolType::IP);
            }
            
            if (packet.ip.header_length() < 20) {
                anomalies_.emplace_back(Anomaly::MALFORMED_HEADER, timestamp_us,
                                       "IP header too short", ProtocolType::IP);
            }
        }
        
        // Check TCP sequence gaps
        if (packet.has_tcp) {
            uint16_t src_port = packet.tcp.get_src_port();
            uint32_t seq = packet.tcp.get_sequence_number();
            uint16_t seq_low = static_cast<uint16_t>(seq & 0xFFFF);
            
            // Fix Bug 6: Use find() instead of != 0 check to properly handle sequence number 0
            // A sequence number of 0 is valid, so we need to track if we've seen this port before
            auto tcp_it = last_tcp_seq_.find(src_port);
            if (tcp_it != last_tcp_seq_.end()) {
                // We've seen this port before, check for gaps
                uint16_t last_seq = tcp_it->second;
                uint16_t expected = (last_seq == 65535) ? 0 : (last_seq + 1);
                
                if (seq_low != expected && !packet.tcp.has_syn()) {
                    // Allow for wrap-around
                    if (seq_low < last_seq && seq_low > 1000) {
                        // Probably wrap-around, skip
                    } else if (seq_low != expected) {
                        anomalies_.emplace_back(Anomaly::SEQUENCE_GAP, timestamp_us,
                                               "TCP sequence gap detected", ProtocolType::TCP);
                    }
                }
                last_tcp_seq_[src_port] = seq_low;
            } else {
                // First time seeing this port, just record the sequence
                last_tcp_seq_[src_port] = seq_low;
            }
        }
        
        // Check UDP payload size mismatch
        if (packet.has_udp) {
            uint16_t declared_len = packet.udp.get_length();
            if (packet.payload_length + 8 != declared_len) {
                anomalies_.emplace_back(Anomaly::PAYLOAD_SIZE_MISMATCH, timestamp_us,
                                       "UDP payload size mismatch", ProtocolType::UDP);
            }
        }
        
        // Check for checksum errors (simplified - would need full validation)
        if (packet.has_ip && !packet.ip.validate_checksum()) {
            anomalies_.emplace_back(Anomaly::CHECKSUM_ERROR, timestamp_us,
                                   "IP checksum validation failed", ProtocolType::IP);
        }
    }
    
    // Get all anomalies
    const std::vector<Anomaly>& get_anomalies() const {
        return anomalies_;
    }
    
    // Get anomaly count
    size_t get_count() const {
        return anomalies_.size();
    }
    
    // Clear anomalies
    void clear() {
        anomalies_.clear();
        last_tcp_seq_.clear();
        last_udp_seq_.clear();
    }
};

#endif // ANOMALY_H

