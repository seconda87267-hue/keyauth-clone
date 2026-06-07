#pragma once
#include <string>
#include <functional>

struct AuthResponse {
    bool success;
    std::string token;
    std::string expires;
    std::string message;
};

class AuthAPI {
public:
    AuthAPI(const std::string& base_url, const std::string& encryption_key = "");

    // Core auth methods
    AuthResponse login(const std::string& license_key, const std::string& hwid, bool encrypted = false);
    bool validate(const std::string& token);
    bool heartbeat(const std::string& token);
    bool reset_hwid(const std::string& license_key, const std::string& admin_key);

    // Check if a response was a rate limit
    bool is_rate_limited(const std::string& response_body);

private:
    std::string m_base_url;
    std::string m_encryption_key;

    std::string http_post(const std::string& endpoint, const std::string& json_body);
    std::string http_get(const std::string& endpoint, const std::string& params);
    std::string build_json(const std::string& key, const std::string& value);
};

struct KeyAuthClient {
    std::string license_key;
    std::string hwid;
    std::string session_token;
    AuthAPI api;

    KeyAuthClient(const std::string& base_url, const std::string& enc_key = "")
        : api(base_url, enc_key) {}

    bool login(const std::string& key);
    bool validate_session();
    bool send_heartbeat();
};
