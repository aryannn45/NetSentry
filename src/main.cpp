#include "netsentry/analyzer.hpp"
#include "netsentry/packet_parser.hpp"
#include "netsentry/pcap_reader.hpp"
#include "netsentry/report_writer.hpp"
#include "netsentry/thread_safe_queue.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <exception>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {

enum class ReportFormat { Both, Json, Csv };

struct Options {
    std::string input_path;
    std::string output_prefix = "netsentry-report";
    std::size_t threads = std::min<std::size_t>(
        8, std::max<std::size_t>(1, std::thread::hardware_concurrency()));
    netsentry::FilterOptions filters;
    netsentry::DetectionOptions detections;
    ReportFormat format = ReportFormat::Both;
};

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool valid_ipv4(const std::string& value) {
    std::size_t start = 0;
    unsigned int octets = 0;
    while (start < value.size()) {
        const std::size_t end = value.find('.', start);
        const std::size_t stop = end == std::string::npos ? value.size() : end;
        if (stop == start || stop - start > 3 ||
            (stop - start > 1 && value[start] == '0')) {
            return false;
        }
        unsigned int octet = 0;
        for (std::size_t i = start; i < stop; ++i) {
            if (!std::isdigit(static_cast<unsigned char>(value[i]))) {
                return false;
            }
            octet = octet * 10U + static_cast<unsigned int>(value[i] - '0');
        }
        if (octet > 255) {
            return false;
        }
        ++octets;
        if (end == std::string::npos) {
            start = value.size();
        } else {
            start = end + 1;
            if (start == value.size()) {
                return false;
            }
        }
    }
    return octets == 4;
}

bool valid_domain(const std::string& domain) {
    if (domain.empty() || domain.size() > 253 || domain.front() == '.' ||
        domain.back() == '.') {
        return false;
    }
    std::size_t label_start = 0;
    while (label_start < domain.size()) {
        const std::size_t dot = domain.find('.', label_start);
        const std::size_t label_end = dot == std::string::npos ? domain.size() : dot;
        const std::size_t length = label_end - label_start;
        if (length == 0 || length > 63 || domain[label_start] == '-' ||
            domain[label_end - 1] == '-') {
            return false;
        }
        for (std::size_t i = label_start; i < label_end; ++i) {
            const unsigned char ch = static_cast<unsigned char>(domain[i]);
            if (!std::isalnum(ch) && ch != '-') {
                return false;
            }
        }
        if (dot == std::string::npos) {
            break;
        }
        label_start = dot + 1;
    }
    return true;
}

std::size_t parse_size(const std::string& text, const std::string& option) {
    if (text.empty() || text[0] == '-') {
        throw std::runtime_error("invalid value for " + option + ": " + text);
    }
    std::size_t consumed = 0;
    unsigned long long value = 0;
    try {
        value = std::stoull(text, &consumed);
    } catch (const std::exception&) {
        throw std::runtime_error("invalid value for " + option + ": " + text);
    }
    if (consumed != text.size() || value > static_cast<unsigned long long>(SIZE_MAX)) {
        throw std::runtime_error("invalid value for " + option + ": " + text);
    }
    return static_cast<std::size_t>(value);
}

std::string require_value(int& index, int argc, char** argv, const std::string& option) {
    if (index + 1 >= argc) {
        throw std::runtime_error("missing value for " + option);
    }
    return argv[++index];
}

void print_help() {
    std::cout
        << "NetSentry " NETSENTRY_VERSION " - offline PCAP traffic analysis\n\n"
        << "Usage: netsentry --input <capture.pcap> [options]\n\n"
        << "Options:\n"
        << "  -i, --input PATH             Classic PCAP input (Ethernet link type)\n"
        << "  -o, --output PREFIX          Report filename prefix (default: netsentry-report)\n"
        << "      --format both|json|csv   Report formats (default: both)\n"
        << "      --threads N              Parser workers (default: up to 8)\n"
        << "      --ip IPv4                 Match either endpoint; may be repeated\n"
        << "      --port N                  Match either endpoint; may be repeated\n"
        << "      --domain NAME             Match DNS, HTTP Host or TLS SNI; may be repeated\n"
        << "      --scan-threshold N        Unique SYN destination ports per source (default: 20)\n"
        << "      --syn-threshold N         Unacknowledged SYNs per destination (default: 100)\n"
        << "  -h, --help                    Show this help\n";
}

Options parse_options(int argc, char** argv) {
    Options options;
    for (int i = 1; i < argc; ++i) {
        const std::string argument = argv[i];
        if (argument == "-h" || argument == "--help") {
            print_help();
            std::exit(0);
        } else if (argument == "-i" || argument == "--input") {
            options.input_path = require_value(i, argc, argv, argument);
        } else if (argument == "-o" || argument == "--output") {
            options.output_prefix = require_value(i, argc, argv, argument);
            if (options.output_prefix.empty()) {
                throw std::runtime_error("--output must not be empty");
            }
        } else if (argument == "--threads") {
            options.threads = parse_size(require_value(i, argc, argv, argument), argument);
            if (options.threads == 0 || options.threads > 64) {
                throw std::runtime_error("--threads must be between 1 and 64");
            }
        } else if (argument == "--ip") {
            const std::string ip = require_value(i, argc, argv, argument);
            if (!valid_ipv4(ip)) {
                throw std::runtime_error("invalid IPv4 address for --ip: " + ip);
            }
            options.filters.ips.insert(ip);
        } else if (argument == "--port") {
            const std::size_t port = parse_size(require_value(i, argc, argv, argument), argument);
            if (port == 0 || port > 65535) {
                throw std::runtime_error("--port must be between 1 and 65535");
            }
            options.filters.ports.insert(static_cast<std::uint16_t>(port));
        } else if (argument == "--domain") {
            std::string domain = lowercase(require_value(i, argc, argv, argument));
            while (!domain.empty() && domain.back() == '.') {
                domain.pop_back();
            }
            if (!valid_domain(domain)) {
                throw std::runtime_error("invalid domain for --domain");
            }
            options.filters.domains.insert(std::move(domain));
        } else if (argument == "--scan-threshold") {
            options.detections.port_scan_threshold =
                parse_size(require_value(i, argc, argv, argument), argument);
        } else if (argument == "--syn-threshold") {
            options.detections.syn_flood_threshold =
                parse_size(require_value(i, argc, argv, argument), argument);
        } else if (argument == "--format") {
            const std::string format = require_value(i, argc, argv, argument);
            if (format == "both") {
                options.format = ReportFormat::Both;
            } else if (format == "json") {
                options.format = ReportFormat::Json;
            } else if (format == "csv") {
                options.format = ReportFormat::Csv;
            } else {
                throw std::runtime_error("--format must be both, json or csv");
            }
        } else {
            throw std::runtime_error("unknown option: " + argument);
        }
    }
    if (options.input_path.empty()) {
        throw std::runtime_error("--input is required");
    }
    return options;
}

double packet_timestamp(const netsentry::PacketRecord& record) {
    const double divisor = record.nanosecond_precision ? 1000000000.0 : 1000000.0;
    return static_cast<double>(record.timestamp_seconds) +
           static_cast<double>(record.timestamp_fraction) / divisor;
}

netsentry::Statistics analyze_capture(const Options& options) {
    netsentry::PcapReader reader(options.input_path);
    netsentry::Analyzer analyzer(options.filters, options.detections);
    netsentry::ThreadSafeQueue<netsentry::PacketRecord> queue(64);
    std::exception_ptr worker_error;
    std::mutex error_mutex;
    std::vector<std::thread> workers;
    workers.reserve(options.threads);
    try {
        for (std::size_t i = 0; i < options.threads; ++i) {
            workers.emplace_back([&queue, &analyzer, &worker_error, &error_mutex] {
                try {
                    netsentry::PacketRecord record;
                    while (queue.pop(record)) {
                        analyzer.consume(netsentry::parse_ethernet_ipv4(record),
                                         packet_timestamp(record));
                    }
                } catch (...) {
                    {
                        std::lock_guard<std::mutex> lock(error_mutex);
                        if (!worker_error) {
                            worker_error = std::current_exception();
                        }
                    }
                    queue.close();
                }
            });
        }
    } catch (...) {
        queue.close();
        for (std::thread& worker : workers) {
            worker.join();
        }
        throw;
    }

    std::exception_ptr input_error;
    try {
        netsentry::PacketRecord record;
        while (reader.next(record)) {
            if (!queue.push(std::move(record))) {
                break;
            }
        }
    } catch (...) {
        input_error = std::current_exception();
    }
    queue.close();
    for (std::thread& worker : workers) {
        worker.join();
    }
    if (input_error) {
        std::rethrow_exception(input_error);
    }
    if (worker_error) {
        std::rethrow_exception(worker_error);
    }
    return analyzer.snapshot();
}

}  // namespace

int main(int argc, char** argv) {
    try {
        const Options options = parse_options(argc, argv);
        const netsentry::Statistics statistics = analyze_capture(options);

        if (options.format == ReportFormat::Both || options.format == ReportFormat::Json) {
            netsentry::write_json_report(options.output_prefix + ".json", statistics);
        }
        if (options.format == ReportFormat::Both || options.format == ReportFormat::Csv) {
            netsentry::write_csv_report(options.output_prefix + ".csv", statistics);
        }

        std::cout << "Analysis complete\n"
                  << "  Packets:      " << statistics.packets << '\n'
                  << "  Bytes:        " << statistics.bytes << '\n'
                  << "  Connections:  " << statistics.connections << '\n'
                  << "  DNS packets:  " << statistics.dns_packets << '\n'
                  << "  Alerts:       " << statistics.alerts.size() << '\n';
        if (options.format == ReportFormat::Both || options.format == ReportFormat::Json) {
            std::cout << "  JSON report:  " << options.output_prefix << ".json\n";
        }
        if (options.format == ReportFormat::Both || options.format == ReportFormat::Csv) {
            std::cout << "  CSV report:   " << options.output_prefix << ".csv\n";
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "NetSentry error: " << error.what() << '\n';
        return 2;
    }
}
