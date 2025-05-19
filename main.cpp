#include <App.h>
#include <iostream>
#include "Headers/connection_data_queue.h"
#include "Headers/conn_data_storage.h"
#include "Headers/conn_thread_pool.h"
#include <bastion_data.h>
#include <parse_message_json.h>
#include <atomic>
#include "Headers/database_head.h"
#include "database_head.h"
#include "Headers/mobile_api_handler.h"
#include "Headers/validation_work.h"
#include "Headers/databaseq.h"
#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <regex>
#include "Headers/validate_username.h"
#include "main_helpers.h"
#include "DatabaseV2/database_comm_v2.h"

#define EMPTY_USERNAME "NOTSET"

/*
 TODO

 - setup proxy to load balance event loop threads - single port delegates to other open ports
 - increase ulimit -n (file descriptor limit)
 - adjust net.core.somaxconn for maximum connections
 - set fs.file-max for max open files
 - thread pool to handle connections
 - new global vector to hold users being processed, if being processed, reject signin

 Avoid Threads Plan:
 - Client site to websocket connection, connection managed by uWebSockets
 - Websocket data stored, request to data daemon made and websock to phone made via uWebSocket
 - Keep both ws connections in data structure, note not signed in yet, unique id.
 - When user approves, update data structure to "ready to approve", send approval to client site
 - No threads


 To be figured out:
 - How to notify connection in structure that it's ready to be sent out?
    Connection sits in structure with websocket connections for both mobile and client site.
    When user approves on mobile, mobile conn manager daemon will need to update that connection.
    Possibly override/make new WebSocketBehavior for uWebSocket

    Solution:
    - Second queue that when the approval is finished, its added to a new queue that can be sent through
        event loop


    - nvm, API POST request to server after push notification to phone
New solution:
- ConnectionDataList stores connections while waiting for mobile verification. then mobile phone sends https POST request
    with the data and then the corresponding connection data is pulled from the list


PROBLEMMMMMMMMM
- STUPID FUCXKING ULIMIT STUCK AT 1000 WONT LET ME CHANGE
- nuking socket connections ahhhhhhh ahhhh ahhh
- works well at 800 so far
 */


ConnThreadPool* g_connThreadPool = nullptr;
std::atomic<int> globalConnectionId{1};

//TODO whether they have an account or not they will signin with username, if we find they have a bastion account and not a site account we send signup, else signin
struct WebSocketBehavior
{
    static void open(uWS::WebSocket<false, true, ConnectionData> *ws)
    {
        auto *connData = ws->getUserData();
        //passing increment amount (1) to the atomic global connection counter
        connData->connection_id = globalConnectionId.fetch_add(1);
        std::cout << "[INFO] Client connected! UserData pointer: " << connData
                  << ", connection id: " << connData->connection_id << std::endl;
    }

    // for inbound message
    // first false is for ssl - false = no ssl
    static void message(uWS::WebSocket<false, true, ConnectionData> *ws, std::string_view message, uWS::OpCode opCode)
    {
        /*
         *Need meta data structure for messages (sign in vs create account)
         */
        std::cout << "[INFO] Client message received: " << message << std::endl;
        /*
        MsgMethod msg_method;
        try {
            msg_method = parse_method(message);
            std::cout << "[DEBUG] Method type: " << msg_method.type << "\n";
            for (const auto &kv : msg_method.keys)
                std::cout << "[DATA] " << kv.first << " : " << kv.second << "\n";
        } catch (const std::exception &ex) {
            std::cerr << "[ERROR] " << ex.what() << "\n";
        } catch (...) {
            std::cerr << "[ERROR] Caught unknown error" << "\n";
        }
        */
        inbound_msg parsed_message{};
        STATUS parse_status = parse_inbound_msg(message, &parsed_message);
        if (parse_status != SUCCESS) {
            std::cerr << "[Error] Failed to parse inbound message.\n";
            return;
        }
        std::cout << "[INFO] Client message parsed:\n";
        std::cout << "[Data] Action: " << parsed_message.action << "\n";
        for (const auto& [key, value] : parsed_message.keys) {
            std::cout << "[Data] Key: " << key << " Value: " << value << "\n";
        }

        /* SIGNIN
         * Shit we should get from client:
         *
         */


        /*
        {
        * ROUTE
          "action": "start_signin",
        * Single Page App id (site id or domain + page)
          "client_id": "your-spa-id",
        * Username to be validated
          "username": "test",
        * This will be stored, server will later ask for raw version, re-hash, and check it matches
          "code_challenge": "YQGUMX2wDOj_FWCObHGbgVXtV9gnFjSHQDLzgGdS2Rk",
        * Re-hash the challenge code
          "code_challenge_method": "S256",
        * This gets sent back to client unchanged to match against client version
          "state": "88c7096b3943c7a685e55a491abb61e3"
        }

        FLOW:
        1. Browser sends username, SPA, action, code challenge, challenge method, and state
        2. Server stores all the above, generates transaction id, and begins validation with mobile app
        3. Server sends browser message with the state and transaction id "signin_started"
        lets do this after phone verifies
        4. Server asks for the original code challenge
        5. Server re-hashes code and checks it matches
        6. Server sends browser the approval


        */

        if (parsed_message.action == "start_signin") {
        /*
         *Parse input for validity here, reject bad characters
         */
            std::string rawUsername = parsed_message.keys["username"];
            std::cout << "[DEBUG] Raw username (hex): \n[DATA] ";
            for (unsigned char c : rawUsername) {
                printf("%02x ", c);
            }
            std::cout << std::endl;

            bastion_username user_username{};
            bastion_username *user_username_ptr = &user_username;
            //TODO SUPER IMPORTANT USE SAME PROCESS FUNCTION TO VALIDATE USERNAMES AT SIGNUP
            if (setUsername(parsed_message.keys["username"].c_str(), user_username)) {
                std::cout << "[INFO] Username valid.\n";
            } else {
                std::cout << "[INFO] Username contains invalid characters.\n";
                std::string username_verif_ret = R"({"status":"invalid_char"})";
                ws->send(username_verif_ret, uWS::OpCode::TEXT);
                return;
            }

            /*
             *Check is username exists in DB here, reject if not
             */
            bool username_exists;
            bool *username_exists_ptr = &username_exists;
            STATUS username_exists_status = check_username_exists(user_username_ptr, username_exists_ptr);
            if (username_exists_status != SUCCESS) {
                std::cout << "[ERROR] Error checking username.\n";
                std::string user_exists_error = R"({"status": "db_error"})";
                ws->send(user_exists_error, uWS::OpCode::TEXT);
                return;
            }

            if (*username_exists_ptr == false) {
                std::cout << "[INFO] Username does not exist.\n";
                std::string user_exist_false = R"({"status": "user_no_exist"})";
                ws->send(user_exist_false, uWS::OpCode::TEXT);
                return;
            }

           std::cout << "[INFO] Signing in...\n";
           auto *connData = static_cast<ConnectionData*>(ws->getUserData());
            //zero out the user data incase client sends duplicate signins
            if (connData->user_data.being_processed != true) {
                memset(connData->username, 0, sizeof(connData->username));
                connData->user_data = full_user_data(); //default construct it = reset cleanly
                strncpy(connData->username, parsed_message.keys["username"].c_str(), sizeof(connData->username));
                //connData->username = msg_method.keys["username"];
                connData->ws = ws;
                //this will be the unique id to track every transaction
                connData->transaction_id = generate_transaction_id();
                connData->base_64_sha_256_enc_challenge_hash = parsed_message.keys["code_challenge"];
                connData->challenge_method = parsed_message.keys["code_challenge_method"];
                connData->state = parsed_message.keys["state"];
                connData->spa_id = parsed_message.keys["client_id"];
                int site_id = 0;
                STATUS verify_spa_status = verify_spa_and_get_site_id(connData->spa_id, &site_id);
                if (verify_spa_status != SUCCESS) {
                    std::cout << "[Info] Site ID valid.\n";
                    std::string spa_id_failure = R"({"status":"invalid_spa_id"})";
                    ws->send(spa_id_failure, uWS::OpCode::TEXT);
                    return;
                }
                connData->site_id = site_id;

                connData->user_data.being_processed = true;

                g_connThreadPool->enqueueConnection(connData);


                std::cout << "[INFO] Enqueued connection (id: " << connData->connection_id << ")" << "\n";

                std::ostringstream oss;
                oss << "{"
                    << "\"status\":\"valid\","
                    << "\"action\":\"signin_started\","
                    << "\"transaction_id\":\"" << connData->transaction_id << "\","
                    << "\"state\":\""          << connData->state          << "\""
                    << "}";
                std::string json_to_send_to_client = oss.str();
                std::cout << "[DEBUG]" << json_to_send_to_client << "\n";

                ws->send(json_to_send_to_client);
                std::cout << "[INFO] Sign In verification sent back to client\n";

                return;



            } else if (connData->user_data.being_processed == true) {
               //reject sign in attempt, tell current attempt to fail, tell client to retry
                //every step in the process should check the "fail_this" flag to fail it and reject, then tell client
                //they can try again
                connData->user_data.fail_this = true;
                auto* ws = connData->ws;
                std::string wait_msg = R"({"status": "wait"})";
                ws->send(wait_msg, uWS::OpCode::TEXT);
                return;
            }

        }

        if (parsed_message.action == "og_challenge_code_res") {
            auto *connData = static_cast<ConnectionData*>(ws->getUserData());
            std::string transaction_id_temp = parsed_message.keys["transaction_id"];
            if (transaction_id_temp != connData->transaction_id) {
                std::cout << "[INFO] Transaction ID does not match.\n";
                connData->user_data.fail_this = true;
                connData->user_data.being_processed = false;
                return;
            }
            connData->original_challenge_code = parsed_message.keys["code_verifier"];
            connData->user_data.being_processed = false;
            //send approval
            /* DO NOT SEND APPROVAL HERE, SEND IT IN VALIDATION*/
            /*std::string success_msg = R"({"status": "approved"})";
            ws->send(success_msg, uWS::OpCode::TEXT);
            */

            return;
        }

        if (parsed_message.action == "signup") {
            /* This grabs user email for the site and inserts into user_site_data
             */
           std::cout << "[INFO] User requests signup\n";

            return;
        }
        if (parsed_message.action != "signin" || parsed_message.action != "signup") {
           std::cout << "[INFO] Unknown message type, rejecting message.";
            return;
        }

    }


    /* TODO switch to std::shared_pointer
     * Plan is to switch to shared pointers, here we can update a flag in the pointer for when its freed here,
     * then we can check on other locations whether we need to free that shared pointer
     */
    static void close(uWS::WebSocket<false, true, ConnectionData> *ws, int code, std::string_view message)
    {
        auto *connData = ws->getUserData();
        std::cout << "[INFO] Client " << connData->connection_id  << " disconnected!" << std::endl;
    }
};

int main()
{
    uWS::App app;

    /*
    create thread pool to do the work for each connection
    i.e get data, handle data, etc.
    */

    ConnThreadPool local_thread_pool;
    g_connThreadPool = &local_thread_pool;

    std::thread t(api_handler_setup);
    t.detach();


    STATUS start_status = start_db_comm();


    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    setup_threads();
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    // Attach WebSocket route
    // equivalant to app.open = XX, app.close = XX
    app.ws<ConnectionData>("/*", {.open = &WebSocketBehavior::open,
                       .message = &WebSocketBehavior::message,
                       .close = &WebSocketBehavior::close});

    // lambda taking no parameters, token points to listening socket
    app.listen(8443, [](auto *token)
               {
        if (token) {
            std::cout << "[INFO] Server is running on port 8443" << std::endl;
        } else {
            std::cerr << "[ERROR] Failed to start server" << std::endl;
        } });

    // event loop
    app.run();

    void shutdown_db_comm();
    return 0;
}
