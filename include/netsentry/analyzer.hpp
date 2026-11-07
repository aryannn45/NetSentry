#pragma once

#include "netsentry/types.hpp"

#include <deque>
#include <map>
#include <mutex>
#include <set>
#include <string>

namespace netsentry {

class Analyzer {
public:
    Analyzer(FilterOptions filters, DetectionOptions detections);
    void consume(const ParsedPacket& packet, double timestamp_seconds);
    Statistics snapshot() const;

private:
    struct FlowKey {
        std::string first_ip;
        std::string second_ip;
        std::uint16_t first_port = 0;
        std::uint16_t second_port = 0;
        std::uint8_t protocol = 0;

        bool operator<(const FlowKey& other) const;
    };

    bool matches(const ParsedPacket& packet) const;
    FlowKey flow_key(const ParsedPacket& packet) const;
    void detect(const ParsedPacket& packet, double timestamp_seconds);

    FilterOptions filters_;
    DetectionOptions detections_;
    mutable std::mutex mutex_;
    Statistics statistics_;
    std::set<FlowKey> flows_;
    std::map<std::string, std::set<std::uint16_t>> scanned_ports_;
    std::map<std::string, std::size_t> syn_counts_;
    std::set<std::string> scan_alerted_;
    std::set<std::string> syn_alerted_;
};

}  // namespace netsentry
