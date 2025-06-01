//
// Created by root on 5/28/25.
//

#include "../Headers/handler_functionality.h"
#include "global_thread_pool_tmp.h"

//TODO make this an object with more comprehensive functions
//TODO make this NOT pmr, NEED FUCKING MUTEX
std::pmr::unordered_map<std::string, std::string> user_recovery_codes_storage{};


/* TODO
 allocate this on heap, make full class for it.
 it will be unordered_map of "cache" objects.
 every time a signin request is approved or denied, update cache
 flag to whether it should pull new data or not.
 */


namespace nlohmann {
    inline void to_json(json& j, site_data_for_mobile const& data) {
        std::string allow_forwarding = "true";
        if (data.allow_forwarding == 0) {
            allow_forwarding = "false";
        }

        j = nlohmann::json {
                           {"id", data.site_id},
                        {"site_name", data.site_name},
                        {"site_domain", data.site_domain},
                        {"user_email_raw", data.user_email_raw},
                           {"allow_forwarding", allow_forwarding},
                        {"last_used_timestamp", data.last_used_timestamp},
                        {"user_since_timestamp", data.user_since_timestamp}
        };
    }

}

std::string parse_query_parameter(const std::string &query, const std::string &param) {
    std::istringstream ss(query);
    std::string token;
    while (std::getline(ss, token, '&')) {
        size_t eqPos = token.find('=');
        if (eqPos != std::string::npos) {
            std::string key = token.substr(0, eqPos);
            std::string value = token.substr(eqPos + 1);
            if (key == param)
                return value;
        }
    }
    return "";
}

MsgMethod parse_message(std::string rec_json) {
    MsgMethod msg_method;
    try {
        msg_method = parse_method(rec_json);
        std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
        for (const auto &kv : msg_method.keys)
            std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Error: " << ex.what() << "\n";
        return msg_method;
    }
    return msg_method;
}

std::string get_site_data_helper(std::string query) {

    std::string username = parse_query_parameter(query, "username");
    std::cout << "[INFO] Get site data for: username = " << username << "\n";

    std::vector<site_data_for_mobile> site_data;
    STATUS get_site_data_status = get_site_data_for_mobile(&username, &site_data);

    nlohmann::json resp;
    resp["status"]    = (get_site_data_status == SUCCESS ? "valid" : "error");
    resp["site_data"] = site_data;
    std::string body = resp.dump();
    return body;
}

//TODO make more comprehensive
std::string verify_email_helper(std::string query) {
    // GET /email_verif?email=xxx
    std::string email = parse_query_parameter(query, "email");
    if (email.empty()) {
        std::cerr << "[ERROR] Email not provided in query" << std::endl;
        return R"({\"status\":\"email_missing\"})";
    }
    std::cout << "[INFO] Email verification requested for: " << email << std::endl;
    return R"({\"status\":\"email_sent\"})";
}

std::string secure_key_helper(std::string query) {
    std::string username = parse_query_parameter(query, "username");

    //FIX TODO
    if (username.empty()) {
        std::cerr << "[ERROR] Username not provided in query" << std::endl;
        return R"({\"status\": \"username_missing\"})";
    }
    bastion_username temp_username{};
    memcpy(temp_username, username.c_str(), username.length());

    new_user_outbound_data outbound_data{};
    STATUS create_new_user_stat = create_new_user_sec(temp_username, &outbound_data);
    if (create_new_user_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to create new user.\n";
        return R"({"status": "server_failure"})";
    }
    std::string outbound_response;
    outbound_data.secure_type = true;
    STATUS parse_status = process_new_user_to_send(&outbound_data, &outbound_response);
    if (parse_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to parse data to json.\n";
        return R"({"status": "server_failure"})";
    }

    std::cout << "[INFO] Username valid, user added.\n";
    return outbound_response;
}

std::string regular_key_helper(std::string query) {
   std::string username = parse_query_parameter(query, "username");
    if (username.empty()) {
        std::cerr << "[ERROR] Username not provided in query" << std::endl;
        return R"({\"status\": \"username_missing\"})";
    }

    new_user_outbound_data outbound_data{};
    STATUS create_new_user_stat = create_new_user_unsec(username, &outbound_data);
    if (create_new_user_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to create new user.\n";
        std::string resp = R"({"status": "server_failure"})";
        return R"({\"status\": \"server_failure\"})";
    }
    std::string outbound_response;
    outbound_data.secure_type = false;
    STATUS parse_status = process_new_user_to_send(&outbound_data, &outbound_response);
    if (parse_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to parse data to json.\n";
        return R"({\"status\": \"server_failure\"})";
    }

    std::cout << "[INFO] Username valid, user added.\n";
    return outbound_response;
}

std::string recover_by_seed_helper(std::string query) {
    std::string username;
    std::string seed;
    std::istringstream queryStream(query);
    std::string token;
    while (std::getline(queryStream, token, '&')) {
        size_t eqPos = token.find('=');
        if (eqPos != std::string::npos) {
            std::string key = token.substr(0, eqPos);
            std::string value = token.substr(eqPos + 1);
            //inline URL-decode the value
            std::string decoded;
            for (size_t i = 0; i < value.size(); i++) {
                if (value[i] == '%' && i + 2 < value.size()) {
                    std::string hexStr = value.substr(i + 1, 2);
                    char ch = static_cast<char>(std::stoi(hexStr, nullptr, 16));
                    decoded.push_back(ch);
                    i += 2;
                } else if (value[i] == '+') {
                    decoded.push_back(' ');
                } else {
                    decoded.push_back(value[i]);
                }
            }
            if (key == "username") {
                username = decoded;
            } else if (key == "seed") {
                seed = decoded;
            }
        }
    }
    std::cout << "[INFO] Recovery by seed: username = " << username
              << ", seed = " << seed << std::endl;

    //FIX TODO
    if (username.empty()) {
        std::cerr << "[ERROR] Username not provided in query" << std::endl;
        return R"({"status": "username_missing"})";
    }
    bastion_username temp_username{};
    //TODO fucked!
    memcpy(temp_username, username.c_str(), username.length());


    recovered_sec_user_outbound_data outbound_data{};
    STATUS recover_user_stat = recover_user_by_seed_phrase(temp_username, seed, &outbound_data);
    if (recover_user_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to create new user.\n";
        return R"({"status": "server_failure"})";
    }
    std::string outbound_response;
    STATUS parse_status = process_sec_recover_to_send(&outbound_data, &outbound_response);
    if (parse_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to parse data to json.\n";
        return R"({"status": "server_failure"})";
    }

    std::cout << "[INFO] Username valid, user added.\n";
    return outbound_response;
}

std::string signin_response_helper(std::string received_json) {
    /*
     *To validate the sign in when using seed phrase encrypytion, same as before parse keys pass to valid queue, flag will handle switch
     *Only take in key we will store the auth token with the iv to make retrieval easier.
     * Need to add flag on mobile of user type
     *
     *
     */

    //example payload:
    // {"request_id":"69","recovery_method":"seed","approved":true,"site_id":"demo_site_id"}
    std::cout << "[INFO] Received response\n";

    MsgMethod msg_method = parse_message(received_json);
    if (msg_method.keys.find("recovery_method")->second == "seed") {
        auto temp_val = msg_method.keys.find("client_auth_token_enc");
        std::string token_hash_encoded;
        if (temp_val != msg_method.keys.end()) {
            token_hash_encoded = temp_val->second;

        } else {
            return R"({"status":"no_seed_phrase"})";
        }
        temp_val = msg_method.keys.find("connection_id");
        int connection_id;
        if (temp_val != msg_method.keys.end()) {
            connection_id = std::stoi(temp_val->second);
            std::cout << "[INFO] Connection ID: " << connection_id << std::endl;
        } else {
            std::cout << "[ERROR] Connection ID not found" << std::endl;
            return R"({"status":"no_connection_id"})";
        }

        //id_(id), user_id(user_id), token_hash_encoded(token_hash_encoded), sym_key_iv_encoded(sym_key_iv_encoded)
        bool approved_request;
        if (msg_method.keys.find("approved")->second == "true") {
           approved_request = true;
        } else {
            approved_request = false;
        }

        g_workQueue.push(new MyValidationWork(true, 1, 1, connection_id, token_hash_encoded, "catdogahh", approved_request, false, "NO_EMAIL"));

        return R"({"status":"valid"})";
    }

    // double check "email" keyword being sent
    else if (msg_method.keys.find("recovery_method")->second == "email") {
        MsgMethod msg_method_2 = parse_message(received_json);

        /*
         *From here keys and data gets added to thread pool queue for processing
         */

        auto temp_val = msg_method.keys.find("client_auth_token_enc");
        std::string token_hash_encoded;
        if (temp_val != msg_method.keys.end()) {
            token_hash_encoded = temp_val->second;
        } else {
            return R"({"status":"no_auth_token"})";
        }

        temp_val = msg_method.keys.find("symmetric_key_enc");
        std::string sym_key_enc;
        if (temp_val != msg_method.keys.end()) {
            sym_key_enc = temp_val->second;

        } else {
            std::cout << "[ERROR] Sym key not found" << std::endl;
            return R"({"status":"no_sym_key"})";
        }

        temp_val = msg_method.keys.find("connection_id");
        int connection_id;
        if (temp_val != msg_method.keys.end()) {
            connection_id = std::stoi(temp_val->second);
            std::cout << "[INFO] Connection ID: " << connection_id << std::endl;
        } else {
            std::cout << "[ERROR] Connection ID not found" << std::endl;
            return R"({"status":"no_connection_id"})";
        }
        //id_(id), user_id(user_id), token_hash_encoded(token_hash_encoded), sym_key_iv_encoded(sym_key_iv_encoded)
        bool approved_request;
        if (msg_method.keys.find("approved")->second == "true") {
            approved_request = true;
        } else {
            approved_request = false;
        }

        g_workQueue.push(new MyValidationWork(false, 1, 1, connection_id, token_hash_encoded, sym_key_enc, approved_request, false, "NO_EMAIL"));


        return R"({"status":"valid"})";
    }
    else {
        return R"({"status":"no_recovery_method"})";
    }
}

std::string signup_response_helper(std::string received_json) {
    /*
     *This is going to be the exact same fucking thing as a signin except its gonna return an email too
     *
     *DONT FORGET TO HASH THE EMAIL, LOG THE HASh, THEN SEND THE HASH TO THE FUCKING CLIENT
     * NOTES
     * Lets create and cache the hash in the server work thread while we wait, we can just have that ready since we-
     * already know it will be a signup
     */
    //add new fields to DB site_data

    MsgMethod msg_method = parse_message(received_json);
    std::string user_email = msg_method.keys.find("email")->second;
    if (user_email.empty()) {
        return R"({"status": "no_email"})";
    }

    if (msg_method.keys.find("recovery_method")->second == "seed") {
        auto temp_val = msg_method.keys.find("client_auth_token_enc");
        std::string token_hash_encoded;
        if (temp_val != msg_method.keys.end()) {
            token_hash_encoded = temp_val->second;

        } else {
            return R"({"status": "no_token_hash"})";
        }


        temp_val = msg_method.keys.find("connection_id");
        int connection_id;
        if (temp_val != msg_method.keys.end()) {
            connection_id = std::stoi(temp_val->second);
            std::cout << "[INFO] Connection ID: " << connection_id << std::endl;
        } else {
            std::cout << "[ERROR] Connection ID not found" << std::endl;
            return R"({"status": "no_connection_id"})";
        }

        //id_(id), user_id(user_id), token_hash_encoded(token_hash_encoded), sym_key_iv_encoded(sym_key_iv_encoded)
        //ID needs to be random or systematic idk
        bool approved_request;
        if (msg_method.keys.find("approved")->second == "true") {
           approved_request = true;
        } else {
            approved_request = false;
        }

        g_workQueue.push(new MyValidationWork(true, 1, 1, connection_id, token_hash_encoded, "catdogahh", approved_request, true, user_email));

        return R"({"status": "valid"})";
    }

    // double check "email" keyword being sent
    if (msg_method.keys.find("recovery_method")->second == "email") {
        auto temp_val = msg_method.keys.find("client_auth_token_enc");
        std::string token_hash_encoded;
        if (temp_val != msg_method.keys.end()) {
            token_hash_encoded = temp_val->second;

        } else {
            return R"({"status": "no_token_hash"})";
        }

        temp_val = msg_method.keys.find("symmetric_key_enc");
        std::string sym_key_enc;
        if (temp_val != msg_method.keys.end()) {
            sym_key_enc = temp_val->second;

        } else {
            std::cout << "[ERROR] Sym key not found" << std::endl;
            return R"({"status": "no_sym_key"})";
        }

        temp_val = msg_method.keys.find("connection_id");
        int connection_id;
        if (temp_val != msg_method.keys.end()) {
            connection_id = std::stoi(temp_val->second);
            std::cout << "[INFO] Connection ID: " << connection_id << std::endl;
        } else {
            std::cout << "[ERROR] Connection ID not found" << std::endl;
            return R"({"status": "no_connection_id"})";
        }

        bool approved_request;
        if (msg_method.keys.find("approved")->second == "true") {
            approved_request = true;
        } else {
            approved_request = false;
        }

        g_workQueue.push(new MyValidationWork(false, 1, 1, connection_id, token_hash_encoded, sym_key_enc, approved_request, true, user_email));

        return R"({"status": "valid"})";

    }

    return R"({"status": "no_recovery_method"})";
}

std::string device_token_helper(std::string received_json) {
    MsgMethod msg_method;
    std::string username;
    std::string device_token;
    try {
        msg_method = parse_method(received_json);
        std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
        for (const auto &kv : msg_method.keys)
            std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Error: " << ex.what() << "\n";
        return R"({"status" : "server_failure"})";
    }
    if (msg_method.keys.find("device_token") != msg_method.keys.end()) {
        device_token = msg_method.keys["device_token"];
        username = msg_method.keys["username"];
        std::cout << "[DEBUG] Username: " << username << " Device Token: " << device_token << "\n";
    } else {
        std::cerr << "[ERROR] Device message contains no data\n";
        return R"({"status" : "no_device_token"})";
    }

    bastion_username username_bastion;
    strncpy(username_bastion, username.c_str(), 20);

    //STATUS sattyyy = update_device_token_ios_by_username(&username_bastion, &device_token_bastion);
    STATUS sattyyy = insert_ios_device_token_by_username_v2(&username_bastion, &device_token);

    if (sattyyy != SUCCESS) {
        //TODO this will always return success
        std::cerr << "[ERROR] Failed to update device token.\n";
        return R"({"status" : "server_failure"})";
    }
    std::cout << "[INFO] Device token updated.\n";
    return R"({"status" : "valid"})";
}

std::string recovery_code_helper(std::string received_json) {

    //"get" just means send to user email, this should be sent with username, lookup email
    //get code, add to map, wait send to email

    //possible payload: {"request_id":"69", "username": "test121", "email": "test@gmail.com"}
    MsgMethod msg_method;
    std::string username;
    std::string email;
    try {
        msg_method = parse_method(received_json);
        std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
        for (const auto &kv : msg_method.keys)
            std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Error: " << ex.what() << "\n";
        return R"({"status":"error"})";
    }

    if (msg_method.keys.find("username") != msg_method.keys.end() && msg_method.keys.find("email") != msg_method.keys.end()) {
        username = msg_method.keys.find("username")->second;
        email = msg_method.keys.find("email")->second;
        std::cout << "[DEBUG] Username: " << username << " User Email: " << email << "\n";
    } else {
        std::cerr << "[ERROR] Verificatioj message contains no email and/or username\n";
        return R"({"status":"error", "message": "Email or Username missing"})";
    }

    auto email_sender = new EmailSys(&username, &email);
    //TODO make sure this sends, if not send {"status":"error", "message": "Failed to send email"}
    email_sender->send_email_for_verification();
    std::string recovery_code = email_sender->get_verification_code();
    user_recovery_codes_storage[username] = recovery_code;

    return R"({"status":"valid"})";
}

std::string validate_username_helper(std::string received_json) {

    MsgMethod msg_method;
    try {
        msg_method = parse_method(received_json);
        std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
        for (const auto &kv : msg_method.keys)
            std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Error: " << ex.what() << "\n";
        return R"({"status":"error"})";
    }

    std::string username = msg_method.keys["username"];

    bastion_username user_username{};
    //TODO SUPER IMPORTANT USE SAME PROCESS FUNCTION TO VALIDATE USERNAMES AT SIGNUP
    if (setUsername(msg_method.keys["username"].c_str(), user_username)) {
        std::cout << "[INFO] Username valid.\n";
    } else {
        std::cout << "[INFO] Username contains invalid characters.\n";
        return R"({"status":"invalid_char"})";
    }

    /*
     *Check is username exists in DB here, reject if not
     */
    bool username_exists;
    std::string uname_str(user_username);
    STATUS username_exists_status = check_if_username_exists(&uname_str, &username_exists);
    if (username_exists_status != SUCCESS) {
        std::cout << "[ERROR] Error checking username.\n";
        return R"({"status": "db_error"})";
    }

    if (username_exists == true) {
        std::cout << "[INFO] Username already in use.\n";
        return R"({"status": "user_already_exists"})";
    }

    std::cout << "[INFO] Username is valid.\n";
    return R"({"status": "valid"})";
}

std::string verify_code_helper(std::string received_json) {

    MsgMethod msg_method;
    try {
        msg_method = parse_method(received_json);
        std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
        for (const auto &kv : msg_method.keys)
            std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
    } catch (const std::exception &ex) {
        std::cerr << "[ERROR] Error: " << ex.what() << "\n";
        return R"({"status":"error"})";
    }

    std::string username = msg_method.keys["username"];
    std::string inbound_recover_code = msg_method.keys["code"];
    std::cout << "[INFO] Received verification code: " << inbound_recover_code << "\n";

    std::string recovery_code = user_recovery_codes_storage[username];
    std::cout << "[INFO] Verification code from storage: " << recovery_code << "\n";

    if (recovery_code == inbound_recover_code) {
        std::cout << "[INFO] Verified recovery code\n";
        return R"({"verified": true})";
    }

    std::cout << "[INFO] Recovery codes do not match\n";
    return R"({"verified": false, "error": "Invalid verification code"})";
}





