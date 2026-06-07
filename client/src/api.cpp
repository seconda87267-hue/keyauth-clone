#include "api.h"
#include "hwid.h"
#include <curl/curl.h>
#include <sstream>
#include <json/json.h>  // Requires nlohmann/json or similar

static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total = size * nmemb;
    output->append((char*)contents, total);
    return total;
}

AuthAPI::AuthAPI(const std::string& base_url, const std::string& encryption_key)
    : m_base_url(base_url), m_encryption_key(encryption_key) {
    curl_global_init(CURL_GLOBAL_ALL);
}

std::string AuthAPI::http_post(const std::string& endpoint, const std::string& json_body) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    std::string url = m_base_url + endpoint;
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)json_body.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "User-Agent: KeyAuthClient/1.0");
    headers = curl_slist_append(headers, "X-Client-Version: 1.0.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

std::string AuthAPI::http_get(const std::string& endpoint, const std::string& params) {
    CURL* curl = curl_easy_init();
    if (!curl) return "";

    std::string url = m_base_url + endpoint + "?" + params;
    std::string response;

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "User-Agent: KeyAuthClient/1.0");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return response;
}

std::string AuthAPI::build_json(const std::string& key, const std::string& value) {
    return "{\"" + key + "\":\"" + value + "\"}";
}

AuthResponse AuthAPI::login(const std::string& license_key, const std::string& hwid, bool encrypted) {
    AuthResponse resp;
    resp.success = false;

    // Build request body
    std::string body;
    if (encrypted && !m_encryption_key.empty()) {
        // Use encrypted communication
        std::string plaintext = "{\"license\":\"" + license_key + "\",\"hwid\":\"" + hwid + "\"}";
        // Note: actual encryption would use the crypto module
        body = "{\"license\":\"" + license_key + "\",\"hwid\":\"" + hwid + "\",\"encrypted\":false}";
    } else {
        body = "{\"license\":\"" + license_key + "\",\"hwid\":\"" + hwid + "\"}";
    }

    std::string response = http_post("/api/login", body);
    if (response.empty()) {
        resp.message = "No response from server";
        return resp;
    }

    // Parse JSON response (simplified - use a proper JSON lib)
    if (response.find("\"success\":true") != std::string::npos) {
        resp.success = true;
        // Extract token
        auto token_pos = response.find("\"token\":\"");
        if (token_pos != std::string::npos) {
            token_pos += 9;
            auto end = response.find("\"", token_pos);
            if (end != std::string::npos)
                resp.token = response.substr(token_pos, end - token_pos);
        }
        resp.message = "Authenticated";
    } else {
        auto msg_pos = response.find("\"message\":\"");
        if (msg_pos != std::string::npos) {
            msg_pos += 11;
            auto end = response.find("\"", msg_pos);
            if (end != std::string::npos)
                resp.message = response.substr(msg_pos, end - msg_pos);
        } else {
            resp.message = "Login failed";
        }
    }

    return resp;
}

bool AuthAPI::validate(const std::string& token) {
    std::string body = "{\"token\":\"" + token + "\"}";
    std::string response = http_post("/api/validate", body);
    return response.find("\"success\":true") != std::string::npos;
}

bool AuthAPI::heartbeat(const std::string& token) {
    std::string body = "{\"token\":\"" + token + "\"}";
    std::string response = http_post("/api/heartbeat", body);
    return response.find("\"success\":true") != std::string::npos;
}

bool AuthAPI::reset_hwid(const std::string& license_key, const std::string& admin_key) {
    std::string body = "{\"license\":\"" + license_key + "\",\"admin_key\":\"" + admin_key + "\"}";
    std::string response = http_post("/api/reset", body);
    return response.find("\"success\":true") != std::string::npos;
}

bool AuthAPI::is_rate_limited(const std::string& response_body) {
    return response_body.find("rate_limit") != std::string::npos ||
           response_body.find("429") != std::string::npos;
}

// KeyAuthClient implementation
bool KeyAuthClient::login(const std::string& key) {
    license_key = key;
    hwid = hwid::generate();

    auto resp = api.login(license_key, hwid);
    if (resp.success) {
        session_token = resp.token;
    }
    return resp.success;
}

bool KeyAuthClient::validate_session() {
    if (session_token.empty()) return false;
    return api.validate(session_token);
}

bool KeyAuthClient::send_heartbeat() {
    if (session_token.empty()) return false;
    return api.heartbeat(session_token);
}
