#pragma once

#include "netsentry/types.hpp"

#include <cstdint>
#include <fstream>
#include <string>

namespace netsentry {

class PcapReader {
public:
    explicit PcapReader(const std::string& path);
    bool next(PacketRecord& record);

private:
    std::ifstream input_;
    bool little_endian_ = true;
    bool nanosecond_precision_ = false;
    std::uint32_t snap_length_ = 0;
    std::uint32_t link_type_ = 0;

    std::uint32_t read_u32(const std::uint8_t* bytes) const;
};

}  // namespace netsentry
