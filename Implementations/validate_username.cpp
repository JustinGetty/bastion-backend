//
// Created by root on 4/4/25.
//

#include "../Headers/validate_username.h"
#include <bastion_data.h>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <regex>


std::string trim(const std::string &str) {
    auto start = std::find_if_not(str.begin(), str.end(), [](unsigned char c) {
        return std::isspace(c);
    });
    auto end = std::find_if_not(str.rbegin(), str.rend(), [](unsigned char c) {
        return std::isspace(c);
    }).base();
    return (start < end ? std::string(start, end) : std::string());
}

bool isReservedUsername(const std::string &username) {
    static const std::vector<std::string> reserved = {
        "admin", "root", "system", "null", "undefined", "guest"
    };
    for (const auto &r : reserved) {
        if (username == r) {
            return true;
        }
    }
    return false;
}

bool isValidUsername(const std::string &inputUsername) {
    std::string username = trim(inputUsername);
    std::transform(username.begin(), username.end(), username.begin(), ::tolower);

    if (username.size() < MIN_USERNAME_LENGTH) {
        std::cerr << "[INFO] Username must be at least " << MIN_USERNAME_LENGTH << " characters." << std::endl;
        return false;
    }
    if (username.size() >= MAX_USERNAME_LENGTH) {
        std::cerr << "[INFO] Username must be less than " << MAX_USERNAME_LENGTH << " characters." << std::endl;
        return false;
    }

    if (isReservedUsername(username)) {
        std::cerr << "[INFO] Username is reserved." << std::endl;
        return false;
    }

    std::regex pattern("^[a-z0-9_]+$");
    if (!std::regex_match(username, pattern)) {
        std::cerr << "[INFO] Username contains invalid characters. Allowed: letters, digits, and underscores." << std::endl;
        return false;
    }

    if (username.find("__") != std::string::npos) {
        std::cerr << "[INFO] Username cannot contain consecutive underscores." << std::endl;
        return false;
    }

    return true;
}

bool setUsername(const std::string &input, bastion_username &output) {
    if (!isValidUsername(input)) {
        return false;
    }
    std::string normalized = trim(input);
    std::transform(normalized.begin(), normalized.end(), normalized.begin(), ::tolower);

    size_t copyLength = std::min(normalized.size(), static_cast<std::string::size_type>(MAX_USERNAME_LENGTH - 1));
    std::memset(output, 0, sizeof(bastion_username));
    std::memcpy(output, normalized.c_str(), copyLength);
    output[copyLength] = '\0';

    return true;
}
