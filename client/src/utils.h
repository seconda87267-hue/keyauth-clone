#pragma once
#include <string>

namespace utils {

// SHA256 hash
std::string sha256(const std::string& input);

// Trim whitespace
std::string trim(const std::string& str);

// Current timestamp as ISO string
std::string timestamp();

// Random bytes as hex
std::string random_hex(size_t len = 16);

} // namespace utils
