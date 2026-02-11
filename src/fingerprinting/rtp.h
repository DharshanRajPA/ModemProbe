#ifndef RTP_H
#define RTP_H

#include "common.h"
#include "protocols/protocol_parser.h"
#include <cstdint>
#include <cstring>

struct RTPHeader {
    uint8_t version_padding_extension_cc;
    uint8_t marker_payload_type;
    uint16_t sequence_number;
    uint32_t timestamp;
    uint32_t ssrc;
    
    bool parse(const uint8_t* data, size_t len) {
        if (len < 12) {
            return false;
        }
        
        version_padding_extension_cc = data[0];
        marker_payload_type = data[1];
        sequence_number = (static_cast<uint16_t>(data[2]) << 8) | data[3];
        timestamp = (static_cast<uint32_t>(data[4]) << 24) |
                   (static_cast<uint32_t>(data[5]) << 16) |
                   (static_cast<uint32_t>(data[6]) << 8) |
                   data[7];
        ssrc = (static_cast<uint32_t>(data[8]) << 24) |
               (static_cast<uint32_t>(data[9]) << 16) |
               (static_cast<uint32_t>(data[10]) << 8) |
               data[11];
        
        return true;
    }
    
    uint8_t version() const {
        return (version_padding_extension_cc >> 6) & 0x03;
    }
    
    uint16_t get_sequence_number() const {
        return utils::ntohs(sequence_number);
    }
    
    uint32_t get_timestamp() const {
        return utils::ntohl(timestamp);
    }
    
    uint32_t get_ssrc() const {
        return utils::ntohl(ssrc);
    }
    
    uint8_t payload_type() const {
        return marker_payload_type & 0x7F;
    }
};

class RTPDetector {
public:
    // Detect RTP protocol
    static bool detect(const ParsedPacket& packet) {
        if (!packet.has_udp) {
            return false;
        }
        
        // RTP typically uses ports in range 16384-32767 (RTP/RTCP)
        uint16_t src_port = packet.udp.get_src_port();
        uint16_t dst_port = packet.udp.get_dst_port();
        
        if ((src_port >= 16384 && src_port <= 32767) ||
            (dst_port >= 16384 && dst_port <= 32767)) {
            // Check for RTP header
            if (packet.payload && packet.payload_length >= 12) {
                RTPHeader rtp;
                if (rtp.parse(packet.payload, packet.payload_length)) {
                    // RTP version should be 2
                    if (rtp.version() == 2) {
                        return true;
                    }
                }
            }
        }
        
        // Also check common RTP ports (5004, 5005, etc.)
        if (src_port == 5004 || dst_port == 5004 ||
            src_port == 5005 || dst_port == 5005) {
            return true;
        }
        
        return false;
    }
    
    // Detect SIP protocol (often used with RTP)
    static bool detect_sip(const ParsedPacket& packet) {
        if (!packet.has_udp && !packet.has_tcp) {
            return false;
        }
        
        // SIP typically uses port 5060
        uint16_t src_port = 0, dst_port = 0;
        if (packet.has_udp) {
            src_port = packet.udp.get_src_port();
            dst_port = packet.udp.get_dst_port();
        } else if (packet.has_tcp) {
            src_port = packet.tcp.get_src_port();
            dst_port = packet.tcp.get_dst_port();
        }
        
        if (src_port == 5060 || dst_port == 5060) {
            return true;
        }
        
        // Fix Bug 2: Check payload length before matching each string
        // Check for SIP methods in payload with proper length validation
        if (packet.payload) {
            // Check for "SIP/" (4 bytes)
            if (packet.payload_length >= 4 && std::memcmp(packet.payload, "SIP/", 4) == 0) {
                return true;
            }
            // Check for "INVITE" (6 bytes)
            if (packet.payload_length >= 6 && std::memcmp(packet.payload, "INVITE", 6) == 0) {
                return true;
            }
            // Check for "REGISTER" (8 bytes)
            if (packet.payload_length >= 8 && std::memcmp(packet.payload, "REGISTER", 8) == 0) {
                return true;
            }
            // Check for "ACK" (3 bytes)
            if (packet.payload_length >= 3 && std::memcmp(packet.payload, "ACK", 3) == 0) {
                return true;
            }
        }
        
        return false;
    }
};

#endif // RTP_H

