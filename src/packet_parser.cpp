#include "netsentry/packet_parser.hpp"

#include <algorithm>
#include <cctype>
#include <set>
#include <string>

namespace netsentry {
namespace {

bool has_bytes(const std::vector<std::uint8_t>& bytes, std::size_t offset, std::size_t count) {
    return offset <= bytes.size() && count <= bytes.size() - offset;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[offset]) << 8U) |
                                      bytes[offset + 1]);
}

std::string ipv4_text(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return std::to_string(bytes[offset]) + "." + std::to_string(bytes[offset + 1]) + "." +
           std::to_string(bytes[offset + 2]) + "." + std::to_string(bytes[offset + 3]);
}

std::string lowercase(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool decode_dns_name(const std::vector<std::uint8_t>& data, std::size_t start,
                     std::string& name, std::size_t& consumed) {
    std::size_t cursor = start;
    std::size_t bytes_consumed = 0;
    bool jumped = false;
    std::set<std::size_t> visited;
    name.clear();
    consumed = 0;

    for (std::size_t steps = 0; steps < 128; ++steps) {
        if (!has_bytes(data, cursor, 1) || !visited.insert(cursor).second) {
            return false;
        }
        const std::uint8_t length = data[cursor];
        if ((length & 0xc0U) == 0xc0U) {
            if (!has_bytes(data, cursor, 2)) {
                return false;
            }
            const std::size_t pointer = static_cast<std::size_t>(
                ((length & 0x3fU) << 8U) | data[cursor + 1]);
            if (pointer >= data.size()) {
                return false;
            }
            if (!jumped) {
                bytes_consumed += 2;
            }
            cursor = pointer;
            jumped = true;
            continue;
        }
        if ((length & 0xc0U) != 0 || length > 63) {
            return false;
        }
        ++cursor;
        if (!jumped) {
            ++bytes_consumed;
        }
        if (length == 0) {
            consumed = bytes_consumed;
            name = lowercase(name);
            return true;
        }
        if (!has_bytes(data, cursor, length)) {
            return false;
        }
        if (!name.empty()) {
            name.push_back('.');
        }
        for (std::size_t i = 0; i < length; ++i) {
            const unsigned char ch = data[cursor + i];
            if (ch < 0x21 || ch > 0x7e) {
                return false;
            }
            name.push_back(static_cast<char>(ch));
        }
        cursor += length;
        if (!jumped) {
            bytes_consumed += length;
        }
    }
    return false;
}

void parse_dns(const std::vector<std::uint8_t>& payload, std::vector<std::string>& names) {
    if (payload.size() < 12) {
        return;
    }
    const std::uint16_t questions = read_u16(payload, 4);
    if (questions > 64) {
        return;
    }
    std::size_t offset = 12;
    for (std::uint16_t i = 0; i < questions; ++i) {
        std::string name;
        std::size_t consumed = 0;
        if (!decode_dns_name(payload, offset, name, consumed) ||
            !has_bytes(payload, offset + consumed, 4)) {
            return;
        }
        offset += consumed + 4;
        if (!name.empty()) {
            names.push_back(name);
        }
    }
}

std::string http_host(const std::vector<std::uint8_t>& payload) {
    const std::string text(payload.begin(), payload.end());
    const std::size_t line_end = text.find("\r\n");
    if (line_end == std::string::npos) {
        return {};
    }
    const std::string first_line = text.substr(0, line_end);
    const std::size_t first_space = first_line.find(' ');
    if (first_space == std::string::npos) {
        return {};
    }
    const std::string method = first_line.substr(0, first_space);
    static const std::set<std::string> methods{
        "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT"};
    if (methods.count(method) == 0) {
        return {};
    }

    std::size_t line_start = line_end + 2;
    while (line_start < text.size()) {
        const std::size_t end = text.find("\r\n", line_start);
        if (end == std::string::npos || end == line_start) {
            break;
        }
        const std::string line = text.substr(line_start, end - line_start);
        const std::size_t colon = line.find(':');
        if (colon != std::string::npos && lowercase(line.substr(0, colon)) == "host") {
            std::size_t value_start = colon + 1;
            while (value_start < line.size() &&
                   std::isspace(static_cast<unsigned char>(line[value_start]))) {
                ++value_start;
            }
            std::string host = lowercase(line.substr(value_start));
            const std::size_t port = host.rfind(':');
            if (port != std::string::npos && host.find(':') == port) {
                host.resize(port);
            }
            return host;
        }
        line_start = end + 2;
    }
    return {};
}

bool tls_sni(const std::vector<std::uint8_t>& data, std::string& host) {
    if (data.size() < 9 || data[0] != 0x16 || data[1] != 0x03) {
        return false;
    }
    const std::size_t record_length = read_u16(data, 3);
    if (record_length < 4 || record_length > data.size() - 5 || data[5] != 0x01) {
        return false;
    }
    const std::size_t handshake_length =
        (static_cast<std::size_t>(data[6]) << 16U) |
        (static_cast<std::size_t>(data[7]) << 8U) | data[8];
    if (handshake_length > record_length - 4) {
        return false;
    }
    const std::size_t handshake_end = 9 + handshake_length;
    const auto has_handshake_bytes = [&data, handshake_end](std::size_t offset,
                                                            std::size_t count) {
        return offset <= handshake_end && count <= handshake_end - offset &&
               has_bytes(data, offset, count);
    };
    std::size_t offset = 9;
    if (!has_handshake_bytes(offset, 2 + 32 + 1)) {
        return false;
    }
    offset += 2 + 32;
    const std::size_t session_length = data[offset++];
    if (!has_handshake_bytes(offset, session_length + 2)) {
        return false;
    }
    offset += session_length;
    const std::size_t cipher_length = read_u16(data, offset);
    offset += 2;
    if (!has_handshake_bytes(offset, cipher_length + 1)) {
        return false;
    }
    offset += cipher_length;
    const std::size_t compression_length = data[offset++];
    if (!has_handshake_bytes(offset, compression_length + 2)) {
        return false;
    }
    offset += compression_length;
    const std::size_t extensions_length = read_u16(data, offset);
    offset += 2;
    if (!has_handshake_bytes(offset, extensions_length)) {
        return false;
    }
    const std::size_t extensions_end = offset + extensions_length;
    while (offset + 4 <= extensions_end) {
        const std::uint16_t type = read_u16(data, offset);
        const std::size_t length = read_u16(data, offset + 2);
        offset += 4;
        if (!has_handshake_bytes(offset, length) || offset + length > extensions_end) {
            return false;
        }
        if (type == 0 && length >= 5) {
            const std::size_t list_length = read_u16(data, offset);
            std::size_t name_offset = offset + 2;
            const std::size_t list_end = name_offset + list_length;
            if (list_end > offset + length) {
                return false;
            }
            while (name_offset + 3 <= list_end) {
                const std::uint8_t name_type = data[name_offset++];
                const std::size_t name_length = read_u16(data, name_offset);
                name_offset += 2;
                if (!has_handshake_bytes(name_offset, name_length) ||
                    name_offset + name_length > list_end) {
                    return false;
                }
                if (name_type == 0 && name_length != 0) {
                    host.assign(data.begin() + static_cast<std::ptrdiff_t>(name_offset),
                                data.begin() + static_cast<std::ptrdiff_t>(name_offset + name_length));
                    host = lowercase(host);
                    return true;
                }
                name_offset += name_length;
            }
        }
        offset += length;
    }
    return false;
}

}  // namespace

ParsedPacket parse_ethernet_ipv4(const PacketRecord& record) {
    ParsedPacket parsed;
    parsed.wire_bytes = record.original_length;
    const auto& bytes = record.bytes;
    if (!has_bytes(bytes, 0, 14)) {
        parsed.truncated = true;
        return parsed;
    }

    std::size_t offset = 14;
    std::uint16_t ether_type = read_u16(bytes, 12);
    while (ether_type == 0x8100 || ether_type == 0x88a8 || ether_type == 0x9100) {
        if (!has_bytes(bytes, offset, 4)) {
            parsed.truncated = true;
            return parsed;
        }
        ether_type = read_u16(bytes, offset + 2);
        offset += 4;
    }
    if (ether_type != 0x0800) {
        return parsed;
    }
    if (!has_bytes(bytes, offset, 20) || (bytes[offset] >> 4U) != 4) {
        parsed.truncated = true;
        return parsed;
    }

    const std::size_t ip_header_length = static_cast<std::size_t>(bytes[offset] & 0x0fU) * 4U;
    const std::size_t ip_total_length = read_u16(bytes, offset + 2);
    if (ip_header_length < 20 || !has_bytes(bytes, offset, ip_header_length) ||
        ip_total_length < ip_header_length) {
        parsed.truncated = true;
        return parsed;
    }
    const std::size_t captured_ip_length = std::min(ip_total_length, bytes.size() - offset);
    if (captured_ip_length < ip_total_length) {
        parsed.truncated = true;
    }
    parsed.is_ipv4 = true;
    parsed.ip_protocol = bytes[offset + 9];
    parsed.source_ip = ipv4_text(bytes, offset + 12);
    parsed.destination_ip = ipv4_text(bytes, offset + 16);

    const std::uint16_t fragment = read_u16(bytes, offset + 6);
    if ((fragment & 0x1fffU) != 0) {
        return parsed;
    }

    std::size_t transport_offset = offset + ip_header_length;
    std::size_t transport_length = captured_ip_length - ip_header_length;
    if (parsed.ip_protocol == 6) {
        if (transport_length < 20 || !has_bytes(bytes, transport_offset, 20)) {
            parsed.truncated = true;
            return parsed;
        }
        parsed.source_port = read_u16(bytes, transport_offset);
        parsed.destination_port = read_u16(bytes, transport_offset + 2);
        const std::size_t tcp_header_length =
            static_cast<std::size_t>(bytes[transport_offset + 12] >> 4U) * 4U;
        if (tcp_header_length < 20 || tcp_header_length > transport_length) {
            parsed.truncated = true;
            return parsed;
        }
        parsed.tcp_syn = (bytes[transport_offset + 13] & 0x02U) != 0;
        parsed.tcp_ack = (bytes[transport_offset + 13] & 0x10U) != 0;
        parsed.transport_parsed = true;
        transport_offset += tcp_header_length;
        transport_length -= tcp_header_length;
    } else if (parsed.ip_protocol == 17) {
        if (transport_length < 8 || !has_bytes(bytes, transport_offset, 8)) {
            parsed.truncated = true;
            return parsed;
        }
        parsed.source_port = read_u16(bytes, transport_offset);
        parsed.destination_port = read_u16(bytes, transport_offset + 2);
        const std::size_t udp_length = read_u16(bytes, transport_offset + 4);
        if (udp_length < 8) {
            parsed.truncated = true;
            return parsed;
        }
        if (udp_length > transport_length) {
            parsed.truncated = true;
            transport_length -= 8;
        } else {
            transport_length = udp_length - 8;
        }
        parsed.transport_parsed = true;
        transport_offset += 8;
    } else {
        return parsed;
    }

    if (!has_bytes(bytes, transport_offset, transport_length)) {
        parsed.truncated = true;
        return parsed;
    }
    parsed.payload.assign(bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset),
                          bytes.begin() + static_cast<std::ptrdiff_t>(transport_offset +
                                                                     transport_length));
    if (parsed.ip_protocol == 17 &&
        (parsed.source_port == 53 || parsed.destination_port == 53)) {
        parse_dns(parsed.payload, parsed.dns_names);
    } else if (parsed.ip_protocol == 6) {
        parsed.application_domain = http_host(parsed.payload);
        if (parsed.application_domain.empty()) {
            tls_sni(parsed.payload, parsed.application_domain);
        }
    }
    return parsed;
}

}  // namespace netsentry
