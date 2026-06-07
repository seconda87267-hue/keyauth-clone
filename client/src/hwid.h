#pragma once
#include <string>

namespace hwid {

// Generate a system-unique HWID using CPU ID, disk serial, and MAC
// Returns SHA256 hash of the combined hardware data
std::string generate();

// Individual hardware collectors (exposed for testing)
std::string get_cpu_id();
std::string get_disk_serial();
std::string get_mac_address();

} // namespace hwid
