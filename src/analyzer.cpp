#include "netsentry/analyzer.hpp"

#include <algorithm>
#include <utility>

namespace netsentry {

std::string protocol_name(std::uint8_t protocol) {
    switch (protocol) {
        case 6:
            return "TCP";
        case 17:
            return "UDP";
        case 1:
            return "ICMP";
        default:
            return "IP-" + std::to_string(protocol);
    }
}

Analyzer::Analyzer(FilterOptions filters, DetectionOptions detections)
    : filters_(std::move(filters)), detections_(detections) {}

bool Analyzer::FlowKey::operator<(const FlowKey& other) const {
    if (protocol != other.protocol) {
        return protocol < other.protocol;
    }
    if (first_ip != other.first_ip) {
        return first_ip < other.first_ip;
    }
    if (first_port != other.first_port) {
        return first_port < other.first_port;
    }
    if (second_ip != other.second_ip) {
        return second_ip < other.second_ip;
    }
    return second_port < other.second_port;
}

bool Analyzer::matches(const ParsedPacket& packet) const {
    if (!filters_.ips.empty() && filters_.ips.count(packet.source_ip) == 0 &&
        filters_.ips.count(packet.destination_ip) == 0) {
        return false;
    }
    if (!filters_.ports.empty() && filters_.ports.count(packet.source_port) == 0 &&
        filters_.ports.count(packet.destination_port) == 0) {
        return false;
    }
    if (!filters_.domains.empty()) {
        std::vector<std::string> packet_domains = packet.dns_names;
        if (!packet.application_domain.empty()) {
            packet_domains.push_back(packet.application_domain);
        }
        bool found = false;
        for (const std::string& domain : packet_domains) {
            for (const std::string& filter : filters_.domains) {
                if (domain == filter ||
                    (domain.size() > filter.size() &&
                     domain.compare(domain.size() - filter.size(), filter.size(), filter) == 0 &&
                     domain[domain.size() - filter.size() - 1] == '.')) {
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    return true;
}

Analyzer::FlowKey Analyzer::flow_key(const ParsedPacket& packet) const {
    FlowKey key;
    key.protocol = packet.ip_protocol;
    if (packet.source_ip < packet.destination_ip ||
        (packet.source_ip == packet.destination_ip && packet.source_port <= packet.destination_port)) {
        key.first_ip = packet.source_ip;
        key.first_port = packet.source_port;
        key.second_ip = packet.destination_ip;
        key.second_port = packet.destination_port;
    } else {
        key.first_ip = packet.destination_ip;
        key.first_port = packet.destination_port;
        key.second_ip = packet.source_ip;
        key.second_port = packet.source_port;
    }
    return key;
}

void Analyzer::detect(const ParsedPacket& packet, double timestamp_seconds) {
    if (packet.ip_protocol != 6 || !packet.transport_parsed || !packet.tcp_syn ||
        packet.tcp_ack) {
        return;
    }
    auto& ports = scanned_ports_[packet.source_ip];
    ports.insert(packet.destination_port);
    if (detections_.port_scan_threshold > 0 &&
        ports.size() >= detections_.port_scan_threshold &&
        scan_alerted_.insert(packet.source_ip).second) {
        statistics_.alerts.push_back(
            {"port_scan", packet.source_ip, packet.destination_ip, packet.destination_port,
             ports.size(), timestamp_seconds});
    }

    const std::string target =
        packet.destination_ip + ":" + std::to_string(packet.destination_port);
    const std::size_t count = ++syn_counts_[target];
    if (detections_.syn_flood_threshold > 0 &&
        count >= detections_.syn_flood_threshold && syn_alerted_.insert(target).second) {
        statistics_.alerts.push_back(
            {"syn_flood", packet.source_ip, packet.destination_ip, packet.destination_port,
             count, timestamp_seconds});
    }
}

void Analyzer::consume(const ParsedPacket& packet, double timestamp_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (packet.truncated) {
        ++statistics_.truncated_packets;
    }
    if (!packet.is_ipv4 || !matches(packet)) {
        return;
    }

    ++statistics_.packets;
    statistics_.bytes += packet.wire_bytes;
    ++statistics_.ipv4_packets;
    ++statistics_.protocols[protocol_name(packet.ip_protocol)];
    if (packet.ip_protocol == 6) {
        ++statistics_.tcp_packets;
        if (packet.transport_parsed && flows_.insert(flow_key(packet)).second) {
            ++statistics_.connections;
        }
        if (!packet.application_domain.empty()) {
            ++statistics_.domains[packet.application_domain];
        }
        detect(packet, timestamp_seconds);
    } else if (packet.ip_protocol == 17) {
        ++statistics_.udp_packets;
        if (packet.transport_parsed && flows_.insert(flow_key(packet)).second) {
            ++statistics_.connections;
        }
        if (packet.transport_parsed &&
            (packet.source_port == 53 || packet.destination_port == 53)) {
            ++statistics_.dns_packets;
            for (const std::string& name : packet.dns_names) {
                ++statistics_.domains[name];
            }
        }
    } else {
        ++statistics_.other_ip_packets;
    }
}

Statistics Analyzer::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return statistics_;
}

}  // namespace netsentry
