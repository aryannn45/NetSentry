#include "netsentry/analyzer.hpp"
#include "netsentry/packet_parser.hpp"
#include "netsentry/pcap_reader.hpp"
#include "netsentry/report_writer.hpp"
#include "netsentry/thread_safe_queue.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void check(bool condition, const std::string& message) {
    if (!condition) {
        throw std::runtime_error(message);
    }
}

void append_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>(value >> 8U));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void put_u16(std::vector<std::uint8_t>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::uint8_t>(value >> 8U);
    bytes[offset + 1] = static_cast<std::uint8_t>(value & 0xffU);
}

netsentry::PacketRecord make_packet(std::uint8_t protocol, std::uint16_t source_port,
                                    std::uint16_t destination_port,
                                    const std::vector<std::uint8_t>& payload,
                                    std::uint8_t tcp_flags = 0x02) {
    netsentry::PacketRecord record;
    std::vector<std::uint8_t>& frame = record.bytes;
    frame.resize(14, 0);
    frame[12] = 0x08;
    frame[13] = 0x00;
    const std::size_t ip = frame.size();
    frame.resize(frame.size() + 20, 0);
    frame[ip] = 0x45;
    put_u16(frame, ip + 2, static_cast<std::uint16_t>(
                               20 + (protocol == 6 ? 20 : 8) + payload.size()));
    frame[ip + 8] = 64;
    frame[ip + 9] = protocol;
    frame[ip + 12] = 10;
    frame[ip + 15] = 1;
    frame[ip + 16] = 10;
    frame[ip + 19] = 2;
    if (protocol == 6) {
        const std::size_t tcp = frame.size();
        frame.resize(frame.size() + 20, 0);
        put_u16(frame, tcp, source_port);
        put_u16(frame, tcp + 2, destination_port);
        frame[tcp + 12] = 0x50;
        frame[tcp + 13] = tcp_flags;
    } else {
        const std::size_t udp = frame.size();
        frame.resize(frame.size() + 8, 0);
        put_u16(frame, udp, source_port);
        put_u16(frame, udp + 2, destination_port);
        put_u16(frame, udp + 4, static_cast<std::uint16_t>(8 + payload.size()));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    record.original_length = static_cast<std::uint32_t>(frame.size());
    return record;
}

std::vector<std::uint8_t> dns_query() {
    std::vector<std::uint8_t> dns(12, 0);
    dns[5] = 1;
    dns.push_back(3);
    dns.insert(dns.end(), {'w', 'w', 'w'});
    dns.push_back(7);
    dns.insert(dns.end(), {'e', 'x', 'a', 'm', 'p', 'l', 'e'});
    dns.push_back(3);
    dns.insert(dns.end(), {'c', 'o', 'm'});
    dns.push_back(0);
    append_u16(dns, 1);
    append_u16(dns, 1);
    return dns;
}

void append_length_prefixed(std::vector<std::uint8_t>& bytes, std::size_t length) {
    append_u16(bytes, static_cast<std::uint16_t>(length));
}

std::vector<std::uint8_t> tls_client_hello(const std::string& hostname) {
    std::vector<std::uint8_t> server_name;
    append_length_prefixed(server_name, hostname.size() + 3);
    server_name.push_back(0);
    append_length_prefixed(server_name, hostname.size());
    server_name.insert(server_name.end(), hostname.begin(), hostname.end());

    std::vector<std::uint8_t> extension;
    append_u16(extension, 0);
    append_length_prefixed(extension, server_name.size());
    extension.insert(extension.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> body{0x03, 0x03};
    body.resize(body.size() + 32, 0);
    body.push_back(0);
    append_u16(body, 2);
    body.push_back(0x13);
    body.push_back(0x01);
    body.push_back(1);
    body.push_back(0);
    append_length_prefixed(body, extension.size());
    body.insert(body.end(), extension.begin(), extension.end());

    std::vector<std::uint8_t> handshake{0x01,
                                        static_cast<std::uint8_t>((body.size() >> 16U) & 0xffU),
                                        static_cast<std::uint8_t>((body.size() >> 8U) & 0xffU),
                                        static_cast<std::uint8_t>(body.size() & 0xffU)};
    handshake.insert(handshake.end(), body.begin(), body.end());
    std::vector<std::uint8_t> record{0x16, 0x03, 0x01};
    append_u16(record, static_cast<std::uint16_t>(handshake.size()));
    record.insert(record.end(), handshake.begin(), handshake.end());
    return record;
}

void write_le32(std::ofstream& output, std::uint32_t value) {
    for (unsigned int shift = 0; shift < 32; shift += 8) {
        output.put(static_cast<char>((value >> shift) & 0xffU));
    }
}

void test_tcp_http_parse() {
    const std::string request = "GET / HTTP/1.1\r\nHost: Example.COM\r\n\r\n";
    const auto record = make_packet(
        6, 50000, 80, std::vector<std::uint8_t>(request.begin(), request.end()), 0x18);
    const netsentry::ParsedPacket parsed = netsentry::parse_ethernet_ipv4(record);
    check(parsed.is_ipv4, "IPv4 Ethernet frame should parse");
    check(parsed.ip_protocol == 6 && parsed.source_port == 50000 &&
              parsed.destination_port == 80,
          "TCP header should parse");
    check(parsed.application_domain == "example.com", "HTTP Host should be normalized");
}

void test_tls_sni_parse() {
    const auto record =
        make_packet(6, 50001, 443, tls_client_hello("Secure.Example"), 0x18);
    const auto parsed = netsentry::parse_ethernet_ipv4(record);
    check(parsed.application_domain == "secure.example", "TLS ClientHello SNI should parse");
}

void test_dns_parse_and_filter() {
    const auto record = make_packet(17, 53000, 53, dns_query(), 0);
    const netsentry::ParsedPacket parsed = netsentry::parse_ethernet_ipv4(record);
    check(parsed.dns_names.size() == 1 && parsed.dns_names[0] == "www.example.com",
          "DNS question name should parse");

    netsentry::FilterOptions filters;
    filters.domains.insert("example.com");
    netsentry::Analyzer analyzer(filters, {});
    analyzer.consume(parsed, 1.0);
    const auto statistics = analyzer.snapshot();
    check(statistics.packets == 1 && statistics.dns_packets == 1,
          "domain suffix filter should retain matching DNS query");
}

void test_truncated_frame() {
    netsentry::PacketRecord record;
    record.bytes = {0, 1, 2};
    record.original_length = 60;
    const auto parsed = netsentry::parse_ethernet_ipv4(record);
    check(parsed.truncated && !parsed.is_ipv4, "short Ethernet frame should be marked truncated");
    netsentry::Analyzer analyzer({}, {});
    analyzer.consume(parsed, 0.0);
    check(analyzer.snapshot().truncated_packets == 1,
          "truncated records should be counted even when IPv4 could not be parsed");
}

void test_connection_and_detection() {
    netsentry::DetectionOptions detections;
    detections.port_scan_threshold = 2;
    detections.syn_flood_threshold = 2;
    netsentry::Analyzer analyzer({}, detections);
    auto one = netsentry::parse_ethernet_ipv4(make_packet(6, 40000, 80, {}));
    auto two = netsentry::parse_ethernet_ipv4(make_packet(6, 40000, 81, {}));
    analyzer.consume(one, 1.0);
    analyzer.consume(two, 2.0);
    analyzer.consume(one, 3.0);
    const auto statistics = analyzer.snapshot();
    check(statistics.connections == 2, "reverse-independent five-tuple flow tracking should work");
    check(statistics.alerts.size() == 2, "port scan and SYN threshold alerts should be emitted");
}

void test_pcap_reader() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const std::filesystem::path path =
        std::filesystem::temp_directory_path() /
        ("netsentry-test-" + std::to_string(stamp) + ".pcap");
    const auto frame = make_packet(6, 12345, 80, {});
    {
        std::ofstream output(path, std::ios::binary);
        output.put(static_cast<char>(0xd4));
        output.put(static_cast<char>(0xc3));
        output.put(static_cast<char>(0xb2));
        output.put(static_cast<char>(0xa1));
        output.put(static_cast<char>(2));
        output.put(static_cast<char>(0));
        output.put(static_cast<char>(4));
        output.put(static_cast<char>(0));
        write_le32(output, 0);
        write_le32(output, 0);
        write_le32(output, 65535);
        write_le32(output, 1);
        write_le32(output, 10);
        write_le32(output, 250000);
        write_le32(output, static_cast<std::uint32_t>(frame.bytes.size()));
        write_le32(output, frame.original_length);
        output.write(reinterpret_cast<const char*>(frame.bytes.data()),
                     static_cast<std::streamsize>(frame.bytes.size()));
        check(static_cast<bool>(output), "temporary PCAP should be written");
    }
    {
        netsentry::PcapReader reader(path.string());
        netsentry::PacketRecord record;
        check(reader.next(record), "PCAP should contain one packet");
        check(record.timestamp_seconds == 10 && record.timestamp_fraction == 250000 &&
                  record.bytes == frame.bytes,
              "PCAP packet data and timestamp should be read");
        check(!reader.next(record), "PCAP should end cleanly");
    }
    std::ifstream complete_input(path, std::ios::binary);
    const std::vector<char> complete_bytes((std::istreambuf_iterator<char>(complete_input)),
                                           std::istreambuf_iterator<char>());
    complete_input.close();
    const std::filesystem::path truncated_path = path.string() + ".truncated";
    {
        std::ofstream output(truncated_path, std::ios::binary);
        output.write(complete_bytes.data(), 24 + 16 + 3);
        check(static_cast<bool>(output), "truncated PCAP fixture should be written");
    }
    bool rejected_truncated_capture = false;
    try {
        netsentry::PcapReader reader(truncated_path.string());
        netsentry::PacketRecord record;
        reader.next(record);
    } catch (const std::runtime_error&) {
        rejected_truncated_capture = true;
    }
    check(rejected_truncated_capture, "truncated PCAP packet data should report an error");
    std::filesystem::remove(truncated_path);
    std::filesystem::remove(path);
}

void test_queue_shutdown() {
    netsentry::ThreadSafeQueue<int> queue(1);
    check(queue.push(7), "queue should accept an item before close");
    queue.close();
    int item = 0;
    check(queue.pop(item) && item == 7, "queue should drain items after close");
    check(!queue.pop(item), "closed and drained queue should stop consumers");
    check(!queue.push(8), "closed queue should reject new items");
}

void test_report_writers() {
    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const std::filesystem::path base =
        std::filesystem::temp_directory_path() / ("netsentry-report-test-" + std::to_string(stamp));
    const std::filesystem::path json_path = base.string() + ".json";
    const std::filesystem::path csv_path = base.string() + ".csv";
    netsentry::Statistics statistics;
    statistics.packets = 2;
    statistics.domains["host.example"] = 1;
    statistics.alerts.push_back({"port_scan", "192.0.2.1", "198.51.100.1", 443, 5, 12.5});
    netsentry::write_json_report(json_path.string(), statistics);
    netsentry::write_csv_report(csv_path.string(), statistics);

    std::ifstream json_input(json_path, std::ios::binary);
    const std::string json((std::istreambuf_iterator<char>(json_input)),
                           std::istreambuf_iterator<char>());
    std::ifstream csv_input(csv_path, std::ios::binary);
    const std::string csv((std::istreambuf_iterator<char>(csv_input)),
                          std::istreambuf_iterator<char>());
    json_input.close();
    csv_input.close();
    check(json.find("\"packets\": 2") != std::string::npos &&
              json.find("host.example") != std::string::npos &&
              json.find("\"type\": \"port_scan\"") != std::string::npos,
          "JSON report should include summary, domains and alerts");
    check(csv.find("summary,packets,2") != std::string::npos &&
              csv.find("\"host.example\"") != std::string::npos,
          "CSV report should include summary and domain rows");
    std::filesystem::remove(json_path);
    std::filesystem::remove(csv_path);
}

}  // namespace

int main() {
    try {
        test_tcp_http_parse();
        test_tls_sni_parse();
        test_dns_parse_and_filter();
        test_truncated_frame();
        test_connection_and_detection();
        test_pcap_reader();
        test_queue_shutdown();
        test_report_writers();
        std::cout << "All NetSentry tests passed\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "Test failure: " << error.what() << '\n';
        return 1;
    }
}
