cmake_minimum_required(VERSION 3.12)
project(ModemProbe VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Optimization flags
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native")
set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)

# Include directories
include_directories(include)
include_directories(src)

# Source files
set(SOURCES
    src/main.cpp
    src/packet_capture.cpp
    src/protocols/ethernet.cpp
    src/protocols/ip.cpp
    src/fingerprinting/http.cpp
    src/fingerprinting/dns.cpp
    src/fingerprinting/rtp.cpp
    src/fingerprinting/fingerprint.cpp
    src/multimedia/h264.cpp
    src/multimedia/rtp_stream.cpp
)

# Find required libraries
find_package(PkgConfig REQUIRED)

# Find libpcap
pkg_check_modules(PCAP REQUIRED libpcap)
if(NOT PCAP_FOUND)
    message(FATAL_ERROR "libpcap not found. Install with: sudo apt-get install libpcap-dev")
endif()

# Find jsoncpp
pkg_check_modules(JSONCPP REQUIRED jsoncpp)
if(NOT JSONCPP_FOUND)
    message(FATAL_ERROR "jsoncpp not found. Install with: sudo apt-get install libjsoncpp-dev")
endif()

# Include directories from pkg-config
include_directories(${PCAP_INCLUDE_DIRS})
include_directories(${JSONCPP_INCLUDE_DIRS})

# Create executable
add_executable(modemprobe ${SOURCES})

# Link libraries
target_link_libraries(modemprobe
    ${PCAP_LIBRARIES}
    ${JSONCPP_LIBRARIES}
)

# Compiler-specific flags
target_compile_options(modemprobe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)

# Install target
install(TARGETS modemprobe DESTINATION bin)

