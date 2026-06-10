/*
 * KeyAuth C++ Client Example
 * Usage: KeyAuthClient.exe <license_key> [server_url]
 *
 * Compile:
 *   mkdir build && cd build
 *   cmake .. && cmake --build .
 */
#include <iostream>
#include <string>
#include "api.h"
#include "hwid.h"

int main(int argc, char* argv[]) {
    std::string license_key;
    std::string server_url = "https://keyauth-clone-production-22ff.up.railway.app";

    if (argc < 2) {
        std::cout << "KeyAuth C++ Client\n";
        std::cout << "Usage: " << argv[0] << " <license_key> [server_url]\n";
        std::cout << "Enter license key: ";
        std::getline(std::cin, license_key);
        if (license_key.empty()) {
            std::cerr << "No license key provided.\n";
            return 1;
        }
    } else {
        license_key = argv[1];
        if (argc >= 3) server_url = argv[2];
    }

    std::cout << "KeyAuth Client v1.0\n";
    std::cout << "Server: " << server_url << "\n";
    std::cout << "License: " << license_key << "\n\n";

    // Generate and display HWID
    std::string hwid = hwid::generate();
    std::cout << "System HWID: " << hwid << "\n\n";

    // Authenticate
    KeyAuthClient client(server_url);
    std::cout << "Authenticating...\n";

    if (client.login(license_key)) {
        std::cout << "✓ Login successful!\n";
        std::cout << "  Session token: " << client.session_token.substr(0, 32) << "...\n";

        // Validate session
        std::cout << "\nValidating session...\n";
        if (client.validate_session()) {
            std::cout << "✓ Session valid\n";
        } else {
            std::cout << "✗ Session invalid\n";
        }

        // Send heartbeat
        std::cout << "\nSending heartbeat...\n";
        if (client.send_heartbeat()) {
            std::cout << "✓ Heartbeat acknowledged\n";
        } else {
            std::cout << "✗ Heartbeat failed\n";
        }

        std::cout << "\n✓ Authentication complete. All systems go.\n";
        return 0;
    } else {
        std::cerr << "✗ Authentication failed!\n";
        return 1;
    }
}
