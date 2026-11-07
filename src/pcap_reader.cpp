#include "netsentry/pcap_reader.hpp"

#include <array>
#include <stdexcept>

namespace netsentry {
namespace {

constexpr std::uint32_t kMaximumCapturedPacket = 1U * 1024U * 1024U;

bool read_exact(std::ifstream& input, std::uint8_t* destination, std::size_t size) {
    input.read(reinterpret_cast<char*>(destination), static_cast<std::streamsize>(size));
    return input.gcount() == static_cast<std::streamsize>(size);
}

}  // namespace

PcapReader::PcapReader(const std::string& path) : input_(path, std::ios::binary) {
    if (!input_) {
        throw std::runtime_error("cannot open input file: " + path);
    }

    std::array<std::uint8_t, 24> header{};
    if (!read_exact(input_, header.data(), header.size())) {
        throw std::runtime_error("invalid PCAP file: incomplete global header");
    }

    const std::array<std::uint8_t, 4> magic{header[0], header[1], header[2], header[3]};
    if (magic == std::array<std::uint8_t, 4>{0xd4, 0xc3, 0xb2, 0xa1}) {
        little_endian_ = true;
    } else if (magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0xc3, 0xd4}) {
        little_endian_ = false;
    } else if (magic == std::array<std::uint8_t, 4>{0x4d, 0x3c, 0xb2, 0xa1}) {
        little_endian_ = true;
        nanosecond_precision_ = true;
    } else if (magic == std::array<std::uint8_t, 4>{0xa1, 0xb2, 0x3c, 0x4d}) {
        little_endian_ = false;
        nanosecond_precision_ = true;
    } else {
        throw std::runtime_error("invalid PCAP file: unsupported magic number (PCAPNG is not supported)");
    }

    const std::uint16_t major = static_cast<std::uint16_t>(
        little_endian_ ? header[4] | (header[5] << 8U) : (header[4] << 8U) | header[5]);
    const std::uint16_t minor = static_cast<std::uint16_t>(
        little_endian_ ? header[6] | (header[7] << 8U) : (header[6] << 8U) | header[7]);
    if (major != 2 || minor != 4) {
        throw std::runtime_error("unsupported PCAP version (expected 2.4)");
    }

    snap_length_ = read_u32(header.data() + 16);
    link_type_ = read_u32(header.data() + 20) & 0xffffU;
    if (snap_length_ == 0 || snap_length_ > kMaximumCapturedPacket) {
        throw std::runtime_error("invalid PCAP snap length");
    }
    if (link_type_ != 1) {
        throw std::runtime_error("unsupported PCAP link type: expected Ethernet (DLT_EN10MB)");
    }
}

std::uint32_t PcapReader::read_u32(const std::uint8_t* bytes) const {
    if (little_endian_) {
        return static_cast<std::uint32_t>(bytes[0]) |
               (static_cast<std::uint32_t>(bytes[1]) << 8U) |
               (static_cast<std::uint32_t>(bytes[2]) << 16U) |
               (static_cast<std::uint32_t>(bytes[3]) << 24U);
    }
    return (static_cast<std::uint32_t>(bytes[0]) << 24U) |
           (static_cast<std::uint32_t>(bytes[1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[2]) << 8U) |
           static_cast<std::uint32_t>(bytes[3]);
}

bool PcapReader::next(PacketRecord& record) {
    std::array<std::uint8_t, 16> packet_header{};
    input_.read(reinterpret_cast<char*>(packet_header.data()), 1);
    if (input_.gcount() == 0 && input_.eof()) {
        return false;
    }
    if (input_.gcount() != 1 ||
        !read_exact(input_, packet_header.data() + 1, packet_header.size() - 1)) {
        throw std::runtime_error("invalid PCAP file: incomplete packet header");
    }

    const std::uint32_t seconds = read_u32(packet_header.data());
    const std::uint32_t fraction = read_u32(packet_header.data() + 4);
    const std::uint32_t captured_length = read_u32(packet_header.data() + 8);
    const std::uint32_t original_length = read_u32(packet_header.data() + 12);
    const std::uint32_t maximum_fraction = nanosecond_precision_ ? 1000000000U : 1000000U;
    if (fraction >= maximum_fraction) {
        throw std::runtime_error("invalid PCAP file: timestamp fraction is out of range");
    }
    if (captured_length > snap_length_ || captured_length > kMaximumCapturedPacket) {
        throw std::runtime_error("invalid PCAP file: captured packet length exceeds limits");
    }
    if (captured_length > original_length) {
        throw std::runtime_error("invalid PCAP file: captured length exceeds original length");
    }

    record.timestamp_seconds = seconds;
    record.timestamp_fraction = fraction;
    record.nanosecond_precision = nanosecond_precision_;
    record.original_length = original_length;
    record.bytes.resize(captured_length);
    if (captured_length != 0 &&
        !read_exact(input_, record.bytes.data(), record.bytes.size())) {
        throw std::runtime_error("invalid PCAP file: packet data is truncated");
    }
    return true;
}

}  // namespace netsentry
