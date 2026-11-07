#include "netsentry/report_writer.hpp"

#include <fstream>
#include <iomanip>
#include <stdexcept>

namespace netsentry {
namespace {

std::string json_escape(const std::string& value) {
    std::string escaped;
    for (const unsigned char ch : value) {
        switch (ch) {
            case '"':
                escaped += "\\\"";
                break;
            case '\\':
                escaped += "\\\\";
                break;
            case '\b':
                escaped += "\\b";
                break;
            case '\f':
                escaped += "\\f";
                break;
            case '\n':
                escaped += "\\n";
                break;
            case '\r':
                escaped += "\\r";
                break;
            case '\t':
                escaped += "\\t";
                break;
            default:
                if (ch < 0x20) {
                    escaped += '?';
                } else {
                    escaped += static_cast<char>(ch);
                }
        }
    }
    return escaped;
}

std::string csv_escape(const std::string& value) {
    std::string escaped = "\"";
    for (const char ch : value) {
        if (ch == '"') {
            escaped += "\"\"";
        } else {
            escaped += ch;
        }
    }
    escaped += '"';
    return escaped;
}

std::ofstream open_output(const std::string& path) {
    std::ofstream output(path, std::ios::binary);
    if (!output) {
        throw std::runtime_error("cannot open report for writing: " + path);
    }
    return output;
}

}  // namespace

void write_json_report(const std::string& path, const Statistics& statistics) {
    std::ofstream output = open_output(path);
    output << "{\n"
           << "  \"summary\": {\n"
           << "    \"packets\": " << statistics.packets << ",\n"
           << "    \"bytes\": " << statistics.bytes << ",\n"
           << "    \"ipv4_packets\": " << statistics.ipv4_packets << ",\n"
           << "    \"tcp_packets\": " << statistics.tcp_packets << ",\n"
           << "    \"udp_packets\": " << statistics.udp_packets << ",\n"
           << "    \"other_ip_packets\": " << statistics.other_ip_packets << ",\n"
           << "    \"dns_packets\": " << statistics.dns_packets << ",\n"
           << "    \"truncated_packets\": " << statistics.truncated_packets << ",\n"
           << "    \"connections\": " << statistics.connections << "\n"
           << "  },\n"
           << "  \"protocols\": {";
    bool first = true;
    for (const auto& entry : statistics.protocols) {
        output << (first ? "\n" : ",\n") << "    \"" << json_escape(entry.first) << "\": "
               << entry.second;
        first = false;
    }
    if (!statistics.protocols.empty()) {
        output << '\n';
    }
    output << "  },\n  \"domains\": {";
    first = true;
    for (const auto& entry : statistics.domains) {
        output << (first ? "\n" : ",\n") << "    \"" << json_escape(entry.first) << "\": "
               << entry.second;
        first = false;
    }
    if (!statistics.domains.empty()) {
        output << '\n';
    }
    output << "  },\n  \"alerts\": [";
    for (std::size_t i = 0; i < statistics.alerts.size(); ++i) {
        const Alert& alert = statistics.alerts[i];
        output << (i == 0 ? "\n" : ",\n") << "    {\"type\": \"" << json_escape(alert.type)
               << "\", \"source_ip\": \"" << json_escape(alert.source_ip)
               << "\", \"destination_ip\": \"" << json_escape(alert.destination_ip)
               << "\", \"destination_port\": " << alert.destination_port
               << ", \"count\": " << alert.count << ", \"timestamp_seconds\": "
               << std::setprecision(12) << alert.timestamp_seconds << '}';
    }
    if (!statistics.alerts.empty()) {
        output << '\n';
    }
    output << "  ]\n}\n";
    if (!output) {
        throw std::runtime_error("failed while writing JSON report: " + path);
    }
}

void write_csv_report(const std::string& path, const Statistics& statistics) {
    std::ofstream output = open_output(path);
    output << "section,name,value\n"
           << "summary,packets," << statistics.packets << '\n'
           << "summary,bytes," << statistics.bytes << '\n'
           << "summary,ipv4_packets," << statistics.ipv4_packets << '\n'
           << "summary,tcp_packets," << statistics.tcp_packets << '\n'
           << "summary,udp_packets," << statistics.udp_packets << '\n'
           << "summary,other_ip_packets," << statistics.other_ip_packets << '\n'
           << "summary,dns_packets," << statistics.dns_packets << '\n'
           << "summary,truncated_packets," << statistics.truncated_packets << '\n'
           << "summary,connections," << statistics.connections << '\n';
    for (const auto& entry : statistics.protocols) {
        output << "protocol," << csv_escape(entry.first) << ',' << entry.second << '\n';
    }
    for (const auto& entry : statistics.domains) {
        output << "domain," << csv_escape(entry.first) << ',' << entry.second << '\n';
    }
    for (const Alert& alert : statistics.alerts) {
        output << "alert," << csv_escape(alert.type) << ','
               << csv_escape(alert.source_ip + " -> " + alert.destination_ip + ":" +
                             std::to_string(alert.destination_port) + " count=" +
                             std::to_string(alert.count))
               << '\n';
    }
    if (!output) {
        throw std::runtime_error("failed while writing CSV report: " + path);
    }
}

}  // namespace netsentry
