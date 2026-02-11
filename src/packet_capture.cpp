#include "packet_capture.h"
#include <pcap/pcap.h>
#include <cstring>
#include <ctime>
#include <iostream>

PacketCapture::PacketCapture() 
    : handle_(nullptr), device_(""), is_running_(false), ring_buffer_(nullptr) {
}

PacketCapture::~PacketCapture() {
    stop();
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
}

bool PacketCapture::init(const std::string& device, PacketRingBuffer* ring_buffer) {
    if (handle_) {
        pcap_close(handle_);
        handle_ = nullptr;
    }
    
    device_ = device;
    ring_buffer_ = ring_buffer;
    error_msg_.clear();
    
    char errbuf[PCAP_ERRBUF_SIZE];
    handle_ = pcap_open_live(device.c_str(), 65535, 1, 1, errbuf);
    
    if (!handle_) {
        error_msg_ = std::string("Failed to open device: ") + errbuf;
        return false;
    }
    
    // Set non-blocking mode
    if (pcap_setnonblock(handle_, 1, errbuf) == -1) {
        error_msg_ = std::string("Failed to set non-blocking mode: ") + errbuf;
        pcap_close(handle_);
        handle_ = nullptr;
        return false;
    }
    
    return true;
}

bool PacketCapture::start() {
    if (!handle_ || !ring_buffer_) {
        error_msg_ = "Capture not initialized";
        return false;
    }
    
    is_running_ = true;
    return true;
}

void PacketCapture::stop() {
    is_running_ = false;
}

int PacketCapture::process_packet() {
    if (!handle_ || !is_running_) {
        return 0;
    }
    
    struct pcap_pkthdr* pkthdr;
    const u_char* packet;
    
    int result = pcap_next_ex(handle_, &pkthdr, &packet);
    
    if (result == 1) {
        // Packet captured
        process_packet_internal(pkthdr, packet);
        return 1;
    } else if (result == 0) {
        // Timeout (non-blocking mode)
        return 0;
    } else if (result == -1) {
        // Error
        error_msg_ = pcap_geterr(handle_);
        return -1;
    } else if (result == -2) {
        // EOF (shouldn't happen with live capture)
        return -2;
    }
    
    return 0;
}

void PacketCapture::process_packet_internal(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (!ring_buffer_) {
        return;
    }
    
    // Convert timestamp to microseconds
    uint64_t timestamp_us = static_cast<uint64_t>(pkthdr->ts.tv_sec) * 1000000ULL +
                            static_cast<uint64_t>(pkthdr->ts.tv_usec);
    
    // Fix Bug 3: Copy packet data instead of storing pointer
    // libpcap's buffer gets overwritten on each call, so we must copy the data
    Packet pkt(packet, pkthdr->caplen, timestamp_us, 0);
    
    // Try to push to ring buffer
    if (!ring_buffer_->push(pkt)) {
        // Buffer full - in production, we'd handle this (drop packet, log, etc.)
    }
}

void PacketCapture::packet_handler(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    PacketCapture* capture = reinterpret_cast<PacketCapture*>(user);
    capture->process_packet_internal(pkthdr, packet);
}

std::vector<std::string> PacketCapture::get_devices() {
    std::vector<std::string> devices;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    pcap_if_t* interfaces;
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        return devices;
    }
    
    for (pcap_if_t* iface = interfaces; iface != nullptr; iface = iface->next) {
        if (iface->name) {
            devices.push_back(std::string(iface->name));
        }
    }
    
    pcap_freealldevs(interfaces);
    return devices;
}

std::string PacketCapture::get_error() const {
    return error_msg_;
}

