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

//pickup here
// work should be done in server_thread_work.cpp

ConnThreadPool* g_connThreadPool = nullptr;
std::atomic<int> globalConnectionId{1};

bool isValidUsername(const std::string& username) {
    if (username.empty()) {
        std::cerr << "Username is empty." << std::endl;
        return false;
    }
    if (username.size() >= MAX_USERNAME_LENGTH) {
        std::cerr << "Username is too long. Maximum allowed is " << (MAX_USERNAME_LENGTH - 1) << " characters." << std::endl;
        return false;
    }
    for (unsigned char c : username) {
        if (!std::isalpha(c)) {
            std::cerr << "Invalid character in username: '" << c << "'. Only letters are allowed." << std::endl;
            return false;
        }
    }
    return true;
}

STATUS processUsername(const std::string& inputUsername) {
    bastion_username user_username{};

    if (!isValidUsername(inputUsername)) {
        std::cerr << "Username validation failed." << std::endl;
        return USERNAME_VERIFICATION_FAILED;
    }

    size_t copyLength = std::min(inputUsername.size(), static_cast<std::string::size_type>(MAX_USERNAME_LENGTH - 1));
    std::memcpy(user_username, inputUsername.c_str(), copyLength);
    user_username[copyLength] = '\0';

    std::cout << "Username accepted: " << user_username << std::endl;
    return SUCCESS;
}

struct WebSocketBehavior
{
    static void open(uWS::WebSocket<false, true, ConnectionData> *ws)
    {
        auto *connData = ws->getUserData();
        //passing increment amount (1) to the atomic global connection counter
        connData->connection_id = globalConnectionId.fetch_add(1);
        std::cout << "Client connected! UserData pointer: " << connData
                  << ", connection id: " << connData->connection_id << std::endl;
    }

    // for inbound message
    // first false is for ssl - false = no ssl
    static void message(uWS::WebSocket<false, true, ConnectionData> *ws, std::string_view message, uWS::OpCode opCode)
    {
        /*
         *Need meta data structure for messages (sign in vs create account)
         */

        std::cout << "Received: " << message << std::endl;
        MsgMethod msg_method;
        try {
            msg_method = parse_method(message);
            std::cout << "Method type: " << msg_method.type << "\n";
            for (const auto &kv : msg_method.keys)
                std::cout << kv.first << " : " << kv.second << "\n";
        } catch (const std::exception &ex) {
            std::cerr << "Error: " << ex.what() << "\n";
        } catch (...) {
            std::cerr << "Caught unknown error" << "\n";
        }


        /*
         *Parse input for validity here, reject bad characters
         */
        bastion_username user_username{};
        bastion_username *user_username_ptr = &user_username;
        memcpy(user_username, msg_method.keys["username"].c_str(), std::size(user_username));
        //TODO SUPER IMPORTANT USE SAME PROCESS FUNCTION TO VALIDATE USERNAMES AT SIGNUP
        STATUS username_verif_status = processUsername(user_username);

        if (username_verif_status != SUCCESS) {
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

        if (msg_method.type == "signin") {
           std::cout << "Signing in...\n";
           auto *connData = static_cast<ConnectionData*>(ws->getUserData());
            //zero out the user data incase client sends duplicate signins
            if (connData->user_data.being_processed != true) {
                memset(connData->username, 0, sizeof(connData->username));
                connData->user_data = full_user_data(); //default construct it = reset cleanly
                strncpy(connData->username, msg_method.keys["username"].c_str(), sizeof(connData->username));
                //connData->username = msg_method.keys["username"];
                connData->ws = ws;

                ConnectionData* copyData = new ConnectionData(*connData);
                copyData->user_data.being_processed = true;

                g_connThreadPool->enqueueConnection(copyData);
               std::cout << "Enqueued connection (id: " << connData->connection_id << ")" << "\n";
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
        if (msg_method.type == "signup") {
           std::cout << "User requests signup\n";
            return;
        }
        if (msg_method.type != "signin" || msg_method.type != "signup") {
           std::cout << "Unknown message type, rejecting message.";
            return;
        }

    }

    static void close(uWS::WebSocket<false, true, ConnectionData> *ws, int code, std::string_view message)
    {
        auto *connData = ws->getUserData();
        std::cout << "Client " << connData->connection_id  << " disconnected!" << std::endl;
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
            std::cout << "Server is running on port 8443" << std::endl;
        } else {
            std::cerr << "Failed to start server" << std::endl;
        } });

    // event loop
    app.run();
    return 0;
}
