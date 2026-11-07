#pragma once

#include "netsentry/types.hpp"

namespace netsentry {

ParsedPacket parse_ethernet_ipv4(const PacketRecord& record);

}  // namespace netsentry
