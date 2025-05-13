//
// Created by root on 3/20/25.
//

#include "../Headers/parse_message_json.h"
#include <iostream>
#include <string>
#include <map>
#include <cctype>
#include <stdexcept>
#include <string_view>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

STATUS parse_inbound_msg(std::string_view msg_json, inbound_msg* msg_map) {
    try {
        auto j = json::parse(msg_json);

        if (auto it = j.find("action"); it != j.end() && it->is_string()) {
            msg_map->action = it->get<std::string>();
        } else {
            msg_map->action.clear();
        }

        for (auto& [key, val] : j.items()) {
            if (key == "action") continue;
            if (val.is_string()) {
                msg_map->keys[key] = val.get<std::string>();
            } else {
                msg_map->keys[key] = val.dump();
            }
        }

        return SUCCESS;
    }

    catch (const json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << "\n";
        return UNKNOWN_FAILURE;
    }
    catch (const json::type_error& e) {
        std::cerr << "Type error: " << e.what() << "\n";
        return UNKNOWN_FAILURE;
    }
}

inline const char* skip_ws(const char* p, const char* end) {
    while (p < end && std::isspace(*p))
        ++p;
    return p;
}

inline std::string parse_string(const char*& p, const char* end) {
    std::string result;
    if (p < end && *p == '\"') {
        ++p;
        while (p < end && *p != '\"') {
            result.push_back(*p);
            ++p;
        }
        if (p < end) ++p;
    }
    return result;
}

inline std::string parse_literal(const char*& p, const char* end) {
    std::string result;
    while (p < end && *p != ',' && *p != '}' && !std::isspace(*p)) {
        result.push_back(*p);
        ++p;
    }
    return result;
}

MsgMethod parse_method(std::string_view json) {
    MsgMethod m;
    const char* p = json.data();
    const char* end = p + json.size();

    p = skip_ws(p, end);
    if (p >= end || *p != '{')
        throw std::runtime_error("Expected '{' at beginning");
    ++p;

    p = skip_ws(p, end);
    if (p >= end || *p != '\"')
        throw std::runtime_error("Expected method type string");
    m.type = parse_string(p, end);

    p = skip_ws(p, end);
    if (p >= end || *p != ':')
        throw std::runtime_error("Expected ':' after method type");
    ++p;

    p = skip_ws(p, end);
    if (p >= end || *p != '[')
        throw std::runtime_error("Expected '[' for array of objects");
    ++p;

    p = skip_ws(p, end);
    if (p >= end || *p != '{')
        throw std::runtime_error("Expected '{' for object in array");
    ++p;

    while (true) {
        p = skip_ws(p, end);
        if (p < end && *p == '}') {
            ++p;
            break;
        }
        if (p >= end || *p != '\"')
            throw std::runtime_error("Expected '\"' for key");
        std::string key = parse_string(p, end);

        p = skip_ws(p, end);
        if (p >= end || *p != ':')
            throw std::runtime_error("Expected ':' after key");
        ++p;

        p = skip_ws(p, end);
        std::string value;
        if (p < end && *p == '\"') {
            value = parse_string(p, end);
        } else {
            value = parse_literal(p, end);
        }
        m.keys[key] = value;

        p = skip_ws(p, end);
        if (p < end && *p == ',') {
            ++p;
        }
    }


    p = skip_ws(p, end);
    if (p < end && *p == ']')
        ++p;
    p = skip_ws(p, end);
    if (p < end && *p == '}')
        ++p;

    return m;
}

/*
int main() {
    std::string json_str = R"({"signin" : [{ "username":"test", "authtoken":"123456" }]})";
    try {
        Method m = parse_method(json_str);
        std::cout << "Method type: " << m.type << "\n";
        for (const auto &kv : m.keys)
            std::cout << kv.first << " : " << kv.second << "\n";
    } catch (const std::exception &ex) {
        std::cerr << "Error: " << ex.what() << "\n";
    }
    return 0;
}
*/
