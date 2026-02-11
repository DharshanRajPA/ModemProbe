#ifndef HTTP_H
#define HTTP_H

#include "common.h"
#include "../protocols/protocol_parser.h"
#include <string>
#include <cstring>

class HTTPDetector {
public:
    // Detect HTTP protocol
    static bool detect(const ParsedPacket& packet) {
        if (!packet.has_tcp && !packet.has_udp) {
            return false;
        }
        
        // Check common HTTP ports
        if (packet.has_tcp) {
            uint16_t src_port = packet.tcp.get_src_port();
            uint16_t dst_port = packet.tcp.get_dst_port();
            
            if (src_port == 80 || dst_port == 80 ||
                src_port == 8080 || dst_port == 8080 ||
                src_port == 8000 || dst_port == 8000) {
                return true;
            }
        }
        
        // Check for HTTP method patterns in payload
        if (packet.payload && packet.payload_length >= 4) {
            // Check for "GET ", "POST", "PUT ", "HEAD", "HTTP"
            if (std::memcmp(packet.payload, "GET ", 4) == 0 ||
                std::memcmp(packet.payload, "POST", 4) == 0 ||
                std::memcmp(packet.payload, "PUT ", 4) == 0 ||
                std::memcmp(packet.payload, "HEAD", 4) == 0) {
                return true;
            }
            
            // Check for "HTTP/" in response
            if (packet.payload_length >= 5 &&
                std::memcmp(packet.payload, "HTTP/", 5) == 0) {
                return true;
            }
        }
        
        return false;
    }
    
    // Extract HTTP method if present
    static std::string get_method(const ParsedPacket& packet) {
        if (!packet.payload || packet.payload_length < 4) {
            return "";
        }
        
        // Check each method with proper length validation
        if (packet.payload_length >= 4 && std::memcmp(packet.payload, "GET ", 4) == 0) {
            return "GET";
        }
        if (packet.payload_length >= 4 && std::memcmp(packet.payload, "POST", 4) == 0) {
            return "POST";
        }
        if (packet.payload_length >= 4 && std::memcmp(packet.payload, "PUT ", 4) == 0) {
            return "PUT";
        }
        if (packet.payload_length >= 4 && std::memcmp(packet.payload, "HEAD", 4) == 0) {
            return "HEAD";
        }
        // Fix Bug 1: Check payload length before matching "DELETE" (6 bytes)
        if (packet.payload_length >= 6 && std::memcmp(packet.payload, "DELETE", 6) == 0) {
            return "DELETE";
        }
        
        return "";
    }
};

#endif // HTTP_H

