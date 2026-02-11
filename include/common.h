#ifndef COMMON_H
#define COMMON_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <ctime>
#include <cstdio>
// Platform-specific network headers
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

// Packet structure - stores packet data in a buffer to avoid pointer invalidation
struct Packet {
    std::vector<uint8_t> data;  // Store data copy instead of pointer
    size_t length;
    uint64_t timestamp_us;  // Microseconds since epoch
    uint32_t interface_index;
    
    Packet() : length(0), timestamp_us(0), interface_index(0) {}
    
    Packet(const uint8_t* d, size_t len, uint64_t ts, uint32_t ifidx)
        : data(d, d + len), length(len), timestamp_us(ts), interface_index(ifidx) {}
    
    // Get pointer to data for parsing
    const uint8_t* get_data() const {
        return data.data();
    }
};

// Protocol type enumeration
enum class ProtocolType {
    UNKNOWN,
    ETHERNET,
    IP,
    IPV4,
    IPV6,
    TCP,
    UDP,
    HTTP,
    DNS,
    RTP,
    SIP,
    H264
};

// Utility functions
namespace utils {
    // Convert bytes to hex string
    inline std::string bytes_to_hex(const uint8_t* data, size_t len) {
        const char hex_chars[] = "0123456789ABCDEF";
        std::string result;
        result.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            result += hex_chars[(data[i] >> 4) & 0x0F];
            result += hex_chars[data[i] & 0x0F];
        }
        return result;
    }
    
    // Get current timestamp in microseconds
    inline uint64_t get_timestamp_us() {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        return static_cast<uint64_t>(ts.tv_sec) * 1000000ULL + static_cast<uint64_t>(ts.tv_nsec) / 1000ULL;
    }
    
    // Network byte order conversion wrappers
    // These wrap the standard ntohs/ntohl functions for consistency
    inline uint16_t ntohs(uint16_t val) {
        return ::ntohs(val);
    }
    
    inline uint32_t ntohl(uint32_t val) {
        return ::ntohl(val);
    }
    
    inline uint16_t htons(uint16_t val) {
        return ::htons(val);
    }
    
    inline uint32_t htonl(uint32_t val) {
        return ::htonl(val);
    }
}

#endif // COMMON_H

