#pragma once

#include "netsentry/types.hpp"

#include <string>

namespace netsentry {

void write_json_report(const std::string& path, const Statistics& statistics);
void write_csv_report(const std::string& path, const Statistics& statistics);

}  // namespace netsentry
