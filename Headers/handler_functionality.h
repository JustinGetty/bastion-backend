//
// Created by root on 5/28/25.
//

#ifndef HANDLER_FUNCTIONALITY_H
#define HANDLER_FUNCTIONALITY_H

#include "parse_message_json.h"
#include "cryptography.h"
#include "UserCreation.h"
#include "SeedCipher.h"
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <cstdio>
#include <nlohmann/json.hpp>
#include "validate_username.h"
#include "UserRecovery.h"
#include "EmailRecovery.h"
#include "database_comm_v2.h"
#include "EmailSys.h"
#include "apiHandlerBoostPool.h"



//GET
std::string get_site_data_helper(std::string query);
std::string verify_email_helper(std::string query);
std::string secure_key_helper(std::string query);
std::string regular_key_helper(std::string query);
std::string recover_by_seed_helper(std::string query);

//POST
std::string signin_response_helper(std::string received_json);
std::string signup_response_helper(std::string received_json);
std::string device_token_helper(std::string received_json);
std::string recovery_code_helper(std::string received_json);
std::string validate_username_helper(std::string received_json);
std::string verify_code_helper(std::string received_json);

#endif //HANDLER_FUNCTIONALITY_H
