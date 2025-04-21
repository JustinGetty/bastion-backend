//
// Created by root on 3/20/25.
//

#ifndef PARSE_MESSAGE_JSON_H
#define PARSE_MESSAGE_JSON_H
#include <iostream>
#include <map>
#include <nlohmann/json.hpp>
#include <bastion_data.h>

typedef struct inbound_msg {
    std::string action;
    std::map<std::string, std::string> keys;
} inbound_msg;

/* newer system --------- */
STATUS parse_inbound_msg(std::string_view msg_json, inbound_msg* msg_map);

struct MsgMethod {
    std::string type;
    std::map<std::string, std::string> keys;
};

inline const char* skip_ws(const char* p, const char* end);
inline std::string parse_string(const char*& p, const char* end);
inline std::string parse_literal(const char*& p, const char* end);
MsgMethod parse_method(std::string_view json);


#endif //PARSE_MESSAGE_JSON_H
