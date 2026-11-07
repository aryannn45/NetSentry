#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace netsentry {

struct PacketRecord {
    std::uint32_t timestamp_seconds = 0;
    std::uint32_t timestamp_fraction = 0;
    bool nanosecond_precision = false;
    std::uint32_t original_length = 0;
    std::vector<std::uint8_t> bytes;
};

struct ParsedPacket {
    bool is_ipv4 = false;
    bool truncated = false;
    bool transport_parsed = false;
    std::string source_ip;
    std::string destination_ip;
    std::uint8_t ip_protocol = 0;
    std::uint16_t source_port = 0;
    std::uint16_t destination_port = 0;
    bool tcp_syn = false;
    bool tcp_ack = false;
    std::uint32_t wire_bytes = 0;
    std::vector<std::uint8_t> payload;
    std::vector<std::string> dns_names;
    std::string application_domain;
};

struct FilterOptions {
    std::set<std::string> ips;
    std::set<std::uint16_t> ports;
    std::set<std::string> domains;
};

struct DetectionOptions {
    std::size_t port_scan_threshold = 20;
    std::size_t syn_flood_threshold = 100;
};

struct Alert {
    std::string type;
    std::string source_ip;
    std::string destination_ip;
    std::uint16_t destination_port = 0;
    std::size_t count = 0;
    double timestamp_seconds = 0.0;
};

struct Statistics {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t ipv4_packets = 0;
    std::uint64_t tcp_packets = 0;
    std::uint64_t udp_packets = 0;
    std::uint64_t other_ip_packets = 0;
    std::uint64_t dns_packets = 0;
    std::uint64_t truncated_packets = 0;
    std::uint64_t connections = 0;
    std::map<std::string, std::uint64_t> protocols;
    std::map<std::string, std::uint64_t> domains;
    std::vector<Alert> alerts;
};

std::string protocol_name(std::uint8_t protocol);

}  // namespace netsentry
