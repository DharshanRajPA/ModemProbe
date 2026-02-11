cmake_minimum_required(VERSION 3.16)
project(ModemProbe VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(MODEMPROBE_ENABLE_RAW_SOCKET "Enable AF_PACKET raw-socket capture (Linux only)" OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)
pkg_check_modules(JSONCPP REQUIRED jsoncpp)

add_executable(modemprobe
  src/main.cpp
  src/capture_pcap.cpp
  src/raw_socket.cpp
  src/parse.cpp
  src/fingerprint.cpp
  src/rtp_stream.cpp
  src/anomaly.cpp
  src/wireless_sim.cpp
  src/report_json.cpp
)

target_include_directories(modemprobe PRIVATE
  ${PCAP_INCLUDE_DIRS}
  ${JSONCPP_INCLUDE_DIRS}
  ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_compile_options(modemprobe PRIVATE -Wall -Wextra -Wpedantic)

target_compile_definitions(modemprobe PRIVATE
  $<$<BOOL:${MODEMPROBE_ENABLE_RAW_SOCKET}>:MODEMPROBE_ENABLE_RAW_SOCKET=1>
)

target_link_libraries(modemprobe PRIVATE
  ${PCAP_LIBRARIES}
  ${JSONCPP_LIBRARIES}
)

install(TARGETS modemprobe DESTINATION bin)
