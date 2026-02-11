#ifndef PROTOCOL_PARSER_H
#define PROTOCOL_PARSER_H

#include "common.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include <vector>
#include <cstddef>

// Parsed packet information
struct ParsedPacket {
    EthernetHeader ethernet;
    IPHeader ip;
    TCPHeader tcp;
    UDPHeader udp;
    
    ProtocolType protocol_type;
    const uint8_t* payload;
    size_t payload_length;
    
    bool has_ethernet;
    bool has_ip;
    bool has_tcp;
    bool has_udp;
    
    ParsedPacket() 
        : protocol_type(ProtocolType::UNKNOWN),
          payload(nullptr),
          payload_length(0),
          has_ethernet(false),
          has_ip(false),
          has_tcp(false),
          has_udp(false) {}
};

class ProtocolParser {
public:
    // Parse a packet from raw data
    static bool parse(const Packet& packet, ParsedPacket& result) {
        result = ParsedPacket();
        
        if (packet.length == 0) {
            return false;
        }
        
        // Use get_data() to get pointer to stored data
        const uint8_t* data = packet.get_data();
        size_t remaining = packet.length;
        size_t offset = 0;
        
        // Parse Ethernet header
        if (remaining >= EthernetHeader::header_size()) {
            if (result.ethernet.parse(data + offset, remaining - offset)) {
                result.has_ethernet = true;
                offset += EthernetHeader::header_size();
                remaining -= EthernetHeader::header_size();
                result.protocol_type = ProtocolType::ETHERNET;
            }
        }
        
        // Parse IP header if EtherType indicates IP
        if (result.has_ethernet && result.ethernet.is_ip() && remaining >= 20) {
            if (result.ip.parse(data + offset, remaining - offset)) {
                result.has_ip = true;
                size_t ip_header_len = result.ip.header_length();
                offset += ip_header_len;
                remaining -= ip_header_len;
                result.protocol_type = ProtocolType::IPV4;
                
                // Parse TCP or UDP
                if (result.ip.is_tcp() && remaining >= 20) {
                    if (result.tcp.parse(data + offset, remaining - offset)) {
                        result.has_tcp = true;
                        size_t tcp_header_len = result.tcp.header_length();
                        offset += tcp_header_len;
                        remaining -= tcp_header_len;
                        result.protocol_type = ProtocolType::TCP;
                    }
                } else if (result.ip.is_udp() && remaining >= 8) {
                    if (result.udp.parse(data + offset, remaining - offset)) {
                        result.has_udp = true;
                        offset += UDPHeader::payload_offset();
                        remaining -= UDPHeader::payload_offset();
                        result.protocol_type = ProtocolType::UDP;
                    }
                }
                
                // Extract payload
                if (remaining > 0) {
                    result.payload = data + offset;
                    result.payload_length = remaining;
                }
            }
        }
        
        return result.has_ethernet;
    }
};

#endif // PROTOCOL_PARSER_H

