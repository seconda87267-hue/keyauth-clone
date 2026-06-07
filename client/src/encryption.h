#pragma once
#include <string>

namespace crypto {

// AES-256-CBC encrypt/decrypt
// Key is derived via SHA256 of the base key string
std::string encrypt(const std::string& plaintext, const std::string& key);
std::string decrypt(const std::string& ciphertext_b64, const std::string& key);

// HMAC-SHA256 request signing
std::string sign(const std::string& data, const std::string& secret);
bool verify(const std::string& data, const std::string& signature, const std::string& secret);

// Base64 encoding/decoding
std::string base64_encode(const unsigned char* data, size_t len);
std::string base64_decode(const std::string& encoded);

// Hex encode
std::string hex_encode(const unsigned char* data, size_t len);

} // namespace crypto
