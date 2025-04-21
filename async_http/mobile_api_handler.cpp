#include "mobile_api_handler.h"
#include "conn_data_storage.h"
#include "parse_message_json.h"
#include "cryptography.h"
#include "UserCreation.h"
#include "SeedCipher.h"
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio.hpp>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <cstdio>
#include <nlohmann/json.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "../Headers/validation_work.h"
#include "../Validation/validation_work.h"
#include "idek_what_this_shits_for_anymore.h"
#include "global_thread_pool_tmp.h"
#include "validate_username.h"
#include "UserRecovery.h"
#include "EmailRecovery.h"

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

extern EmailRecovery email_recovery_obj();

beast::string_view mime_type(beast::string_view path)
{
    using beast::iequals;
    auto const ext = [&path]
    {
        auto const pos = path.rfind(".");
        if(pos == beast::string_view::npos)
            return beast::string_view{};
        return path.substr(pos);
    }();
    if(iequals(ext, ".htm"))  return "text/html";
    if(iequals(ext, ".html")) return "text/html";
    if(iequals(ext, ".php"))  return "text/html";
    if(iequals(ext, ".css"))  return "text/css";
    if(iequals(ext, ".txt"))  return "text/plain";
    if(iequals(ext, ".js"))   return "application/javascript";
    if(iequals(ext, ".json")) return "application/json";
    if(iequals(ext, ".xml"))  return "application/xml";
    // ... other mappings if needed ...
    return "application/text";
}

class http_worker {
public:
    http_worker(http_worker const&) = delete;
    http_worker& operator=(http_worker const&) = delete;

    http_worker(tcp::acceptor& acceptor, const std::string& doc_root) :
        acceptor_(acceptor),
        doc_root_(doc_root)
    {
    }

    void start()
    {
        accept();
        check_deadline();
    }

private:
    using alloc_t = std::allocator<char>;
    // We use a string_body for both incoming requests and outgoing responses.
    using request_body_t = http::string_body;

    // The acceptor used to listen for incoming connections.
    tcp::acceptor& acceptor_;

    // The document root is unused in this JSON-only version,
    // but we leave it here for potential future use.
    std::string doc_root_;

    // The socket for the currently connected client.
    tcp::socket socket_{acceptor_.get_executor()};

    // Buffer used for reading.
    beast::flat_static_buffer<8192> buffer_;

    // Allocator for header fields.
    alloc_t alloc_{};

    // HTTP request parser.
    boost::optional<http::request_parser<request_body_t, alloc_t>> parser_;

    // Deadline timer for the request.
    net::steady_timer request_deadline_{
        acceptor_.get_executor(), (std::chrono::steady_clock::time_point::max)()};

    // Optional response and serializer objects for string-based (JSON) responses.
    boost::optional<http::response<http::string_body, http::basic_fields<alloc_t>>> string_response_;
    boost::optional<http::response_serializer<http::string_body, http::basic_fields<alloc_t>>> string_serializer_;

    // Accept a new connection.
    void accept()
    {
        beast::error_code ec;
        socket_.close(ec);
        buffer_.consume(buffer_.size());

        acceptor_.async_accept(
            socket_,
            [this](beast::error_code ec)
            {
                if (ec)
                {
                    accept();
                }
                else
                {
                    //set deadline, use read_request as callback
                    request_deadline_.expires_after(std::chrono::seconds(60));
                    read_request();
                }
            });
    }

    void read_request()
    {
        parser_.emplace(
            std::piecewise_construct,
            std::make_tuple(),        // Construct message object with default constructor.
            std::make_tuple(alloc_)   // Construct the header fields with our allocator.
        );

        http::async_read(
            socket_,
            buffer_,
            *parser_,
            [this](beast::error_code ec, std::size_t)
            {
                if (ec)
                    accept();
                else
                    process_request(parser_->get());
            });
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

    void process_request(http::request<request_body_t, http::basic_fields<alloc_t>> const& req)
    {

        //get requests
        if(req.method() == http::verb::get)
        {
            std::string targetStr = std::string(req.target());
            // Split into the path and query parts
            size_t pos = targetStr.find('?');
            std::string path = (pos != std::string::npos) ? targetStr.substr(0, pos) : targetStr;
            std::string query = (pos != std::string::npos) ? targetStr.substr(pos + 1) : "";
            //likely never using get, since apple notif will be post to apple ANS server and then post back here
            if (path == "/") {
                send_json_response("{\"message\":\"Hello from GET\"}", http::status::ok);
            }

            //TODO make more comprehensive
            else if (path == "/email_verif") {
                // GET /email_verif?email=xxx
                std::string email = parse_query_parameter(query, "email");
                if (email.empty()) {
                    std::cerr << "[ERROR] Email not provided in query" << std::endl;
                    send_json_response("{\"status\":\"email_missing\"}", http::status::bad_request);
                    return;
                }
                std::cout << "[INFO] Email verification requested for: " << email << std::endl;
                send_json_response("{\"status\":\"email_sent\"}", http::status::ok);
            }







            /*
            * Secure key endpoint, this will ...
            *
             */
            if (path == "/secure_key") {
                std::string username;
                std::istringstream queryStream(query);
                std::string token;
                while (std::getline(queryStream, token, '&')) {
                    size_t eqPos = token.find('=');
                    if (eqPos != std::string::npos) {
                        std::string key = token.substr(0, eqPos);
                        std::string value = token.substr(eqPos + 1);
                        if (key == "username") {
                            username = value;  // You now have the username
                            break;  // Stop once we've found it.
                        }
                    }
                }


                //FIX TODO
                if (username.empty()) {
                    std::cerr << "[ERROR] Username not provided in query" << std::endl;
                    send_json_response("{\"status\": \"username_missing\"}", http::status::bad_request);
                    return;
                }
                bastion_username temp_username{};
                memcpy(temp_username, username.c_str(), username.length());

                new_user_outbound_data outbound_data{};
                STATUS create_new_user_stat = create_new_user_sec(temp_username, &outbound_data);
                if (create_new_user_stat != SUCCESS) {
                    std::cerr << "[ERROR] Failed to create new user.\n";
                    std::string resp = R"({"status": "server_failure"})";
                    send_json_response(resp, http::status::ok);
                }
                std::string outbound_response;
                outbound_data.secure_type = true;
                STATUS parse_status = process_new_user_to_send(&outbound_data, &outbound_response);
                if (parse_status != SUCCESS) {
                    std::cerr << "[ERROR] Failed to parse data to json.\n";
                    std::string resp = R"({"status": "server_failure"})";
                    send_json_response(resp, http::status::ok);
                }

                std::cout << "[INFO] Username valid, user added.\n";
                send_json_response(outbound_response, http::status::ok);
            }



        if (path == "/reg_keys") {
            std::cout << "[INFO] Getting regular keys.\n";
            std::string username;
            std::istringstream queryStream(query);
            std::string token;
            while (std::getline(queryStream, token, '&')) {
                size_t eqPos = token.find('=');
                if (eqPos != std::string::npos) {
                    std::string key = token.substr(0, eqPos);
                    std::string value = token.substr(eqPos + 1);
                    if (key == "username") {
                        username = value;  // You now have the username
                        break;  // Stop once we've found it.
                    }
                }
            }


            //FIX TODO
            if (username.empty()) {
                std::cerr << "[ERROR] Username not provided in query" << std::endl;
                send_json_response("{\"status\": \"username_missing\"}", http::status::bad_request);
                return;
            }
            bastion_username temp_username{};
            memcpy(temp_username, username.c_str(), username.length());

            new_user_outbound_data outbound_data{};
            STATUS create_new_user_stat = create_new_user_unsec(temp_username, &outbound_data);
            if (create_new_user_stat != SUCCESS) {
                std::cerr << "[ERROR] Failed to create new user.\n";
                std::string resp = R"({"status": "server_failure"})";
                send_json_response(resp, http::status::ok);
            }
            std::string outbound_response;
            outbound_data.secure_type = false;
            STATUS parse_status = process_new_user_to_send(&outbound_data, &outbound_response);
            if (parse_status != SUCCESS) {
                std::cerr << "[ERROR] Failed to parse data to json.\n";
                std::string resp = R"({"status": "server_failure"})";
                send_json_response(resp, http::status::ok);
            }

            std::cout << "[INFO] Username valid, user added.\n";
            send_json_response(outbound_response, http::status::ok);
        }


        /* TODO
         * Recover by email flow:
         * Get username
         * Pull email
         * Send code
         * Have user enter code, send to db
         * Codes match? Good
         * Codes dont? Bad
         *
         * NOTES:
         * Do not implement email server yet,
         * wait for other server to be built and reuse
         * For now pretend
         *
         * STRAT:
         * Post request for recovery
         * generates code server side and stores in hash table
         * emails code to user and asks user for code on phone
         * user puts in code which sends a get request with the code asking for new info
         */








            /*
             * print("Mock GET: /recover_account_by_seed?username=\(username)&seed=\(seedPhrase)")
             */

        if (path == "/rec_by_seed") {
            std::string username;
            std::string seed;
            std::istringstream queryStream(query);
            std::string token;
            while (std::getline(queryStream, token, '&')) {
                size_t eqPos = token.find('=');
                if (eqPos != std::string::npos) {
                    std::string key = token.substr(0, eqPos);
                    std::string value = token.substr(eqPos + 1);
                    // Inline URL-decode the value
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


            // perform URL decoding on username here if needed.

            //FIX TODO
            if (username.empty()) {
                std::cerr << "[ERROR] Username not provided in query" << std::endl;
                send_json_response("{\"status\": \"username_missing\"}", http::status::bad_request);
                return;
            }
            bastion_username temp_username{};
            memcpy(temp_username, username.c_str(), username.length());

            recovered_sec_user_outbound_data outbound_data{};
            STATUS recover_user_stat = recover_user_by_seed_phrase(temp_username, seed, &outbound_data);
            if (recover_user_stat != SUCCESS) {
                std::cerr << "[ERROR] Failed to create new user.\n";
                std::string resp = R"({"status": "server_failure"})";
                send_json_response(resp, http::status::ok);
                return;
            }
            std::string outbound_response;
            STATUS parse_status = process_sec_recover_to_send(&outbound_data, &outbound_response);
            if (parse_status != SUCCESS) {
                std::cerr << "[ERROR] Failed to parse data to json.\n";
                std::string resp = R"({"status": "server_failure"})";
                send_json_response(resp, http::status::ok);
                return;
            }

            std::cout << "[INFO] Username valid, user added.\n";
            send_json_response(outbound_response, http::status::ok);


        }




        if (path == "/rec_by_code") {
            /* Requires username and code from email
             * Process:
             * verify code
             * if verifies, recover by email
             * process to json
             * send back user data
             */

            std::string username;
            std::string code_string;
            std::istringstream queryStream(query);
            std::string token;
            while (std::getline(queryStream, token, '&')) {
                size_t eqPos = token.find('=');
                if (eqPos != std::string::npos) {
                    std::string key = token.substr(0, eqPos);
                    std::string value = token.substr(eqPos + 1);
                    // Inline URL-decode the value
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
                        //TODO fix this will break
                    } else if (key == "code") {
                        code_string = decoded;
                    }
                }
            }

        }


    } //end get requests

















        //post requests
        /*
         *READ BACK THE users's sign in details and keys
         *notif to user sent in different thread with APPLE/ANDROID notif services
         */
        else if(req.method() == http::verb::post) {
            std::string target = std::string(req.target());
            std::cout << "[INFO] Target: " << target << "\n";

            if (target == "/reg_signin") {
                std::cout << "[INFO] Processing root target\n";
                const std::string received_json = req.body();

                MsgMethod msg_method;
                try {
                    msg_method = parse_method(received_json);
                    std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
                    for (const auto &kv : msg_method.keys)
                        std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
                } catch (const std::exception &ex) {
                    std::cerr << "[ERROR] Error: " << ex.what() << "\n";
                    return;
                }

                /*
                 *From here keys and data gets added to thread pool queue for processing
                 */

                auto temp_val = msg_method.keys.find("client_auth_token_enc");
                std::string token_hash_encoded;
                if (temp_val != msg_method.keys.end()) {
                    token_hash_encoded = temp_val->second;

                } else {
                    return;
                }

                temp_val = msg_method.keys.find("sym_key_enc");
                std::string sym_key_enc;
                if (temp_val != msg_method.keys.end()) {
                    sym_key_enc = temp_val->second;

                } else {
                    std::cout << "[ERROR] Sym key not found" << std::endl;
                    return;
                }

                temp_val = msg_method.keys.find("connection_id");
                int connection_id;
                if (temp_val != msg_method.keys.end()) {
                    connection_id = std::stoi(temp_val->second);
                    std::cout << "[INFO] Connection ID: " << connection_id << std::endl;
                } else {
                    std::cout << "[ERROR] Connection ID not found" << std::endl;
                    return;
                }

                //error handle here if theyre not found!!


                //id_(id), user_id(user_id), token_hash_encoded(token_hash_encoded), sym_key_iv_encoded(sym_key_iv_encoded)
                //ID needs to be random or systematic idk
                //TODO add type here so SEC can be validated without major rewrite
                g_workQueue.push(new MyValidationWork(false, 1, 1, connection_id, token_hash_encoded, sym_key_enc));


                //send back status response to mobile
                send_json_response(received_json, http::status::ok);

            }

            if (target == "/secure_signin") {

                /*
                 *To validate the sign in when using seed phrase encrypytion, same as before parse keys pass to valid queue, flag will handle switch
                 *Only take in key we will store the auth token with the iv to make retrieval easier.
                 * Need to add flag on mobile of user type
                 */

                //need actual data


                //g_workQueue.push(new MyValidationWork(true, 1, 1, connection_id, token_hash_encoded, sym_key_enc));
            }

            if (target == "/get_recovery_code") {
                //"get" just means send to user email, this should be sent with username, lookup email
                //get code, add to map, wait send to email
            }

        //TODO check both tables for the username not just user
        if (target == "/validate_username") {

            std::string received_json = req.body();
            std::cout << "[DEBUG] Received JSON: " << received_json << "\n";
            MsgMethod msg_method;
            try {
                msg_method = parse_method(received_json);
                std::cout << "[INFO] Method type: " << msg_method.type << std::endl;
                for (const auto &kv : msg_method.keys)
                    std::cout << "[DATA] " << kv.first << " : " << kv.second << std::endl;
            } catch (const std::exception &ex) {
                std::cerr << "[ERROR] Error: " << ex.what() << "\n";
                std::string resp = R"({"status":"error"})";
                send_json_response(resp, http::status::ok);
                return;
            }

            std::string username = msg_method.keys["username"].c_str();

            std::cout << "[DEBUG] Raw username (hex): \n[DATA] ";
            for (unsigned char c : username) {
                printf("%02x ", c);
            }
            std::cout << "\n";

            bastion_username user_username{};
            bastion_username *user_username_ptr = &user_username;
            //TODO SUPER IMPORTANT USE SAME PROCESS FUNCTION TO VALIDATE USERNAMES AT SIGNUP
            if (setUsername(msg_method.keys["username"].c_str(), user_username)) {
                std::cout << "[INFO] Username valid.\n";
            } else {
                std::cout << "[INFO] Username contains invalid characters.\n";
                std::string resp = R"({"status":"invalid_char"})";
                send_json_response(resp, http::status::ok);
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
                std::string resp = R"({"status": "db_error"})";
                send_json_response(resp, http::status::ok);
                return;
            }

            if (*username_exists_ptr == true) {
                std::cout << "[INFO] Username already in use.\n";
                std::string resp = R"({"status": "user_already_exists"})";
                send_json_response(resp, http::status::ok);
                return;
            }

            std::cout << "[INFO] Username is valid.\n";
            std::string resp = R"({"status": "valid"})";
            send_json_response(resp, http::status::ok);



        }
    }


        else
        {
            send_bad_response(
                http::status::bad_request,
                "Invalid request-method '" + std::string(req.method_string()) + "'\r\n");
        }
}
    // Send a generic bad response.
    void send_bad_response(http::status status, std::string const& error)
    {
        string_response_.emplace(
            std::piecewise_construct,
            std::make_tuple(),
            std::make_tuple(alloc_));
        string_response_->result(status);
        string_response_->keep_alive(false);
        string_response_->set(http::field::server, "Beast");
        string_response_->set(http::field::content_type, "text/plain");
        string_response_->body() = error;
        string_response_->prepare_payload();

        string_serializer_.emplace(*string_response_);
        http::async_write(
            socket_,
            *string_serializer_,
            [this](beast::error_code ec, std::size_t)
            {
                socket_.shutdown(tcp::socket::shutdown_send, ec);
                string_serializer_.reset();
                string_response_.reset();
                accept();
            });
    }

    // Helper to send a JSON response.
    void send_json_response(std::string const& body, http::status status = http::status::ok)
    {
        string_response_.emplace(
            std::piecewise_construct,
            std::make_tuple(),
            std::make_tuple(alloc_));
        string_response_->result(status);
        string_response_->keep_alive(false);
        string_response_->set(http::field::server, "Beast");
        string_response_->set(http::field::content_type, "application/json");
        string_response_->body() = body;
        string_response_->prepare_payload();

        string_serializer_.emplace(*string_response_);
        http::async_write(
            socket_,
            *string_serializer_,
            [this](beast::error_code ec, std::size_t)
            {
                socket_.shutdown(tcp::socket::shutdown_send, ec);
                string_serializer_.reset();
                string_response_.reset();
                accept();
            });
    }

    // Periodically check if the request deadline has expired.
    void check_deadline()
    {
        if (request_deadline_.expiry() <= std::chrono::steady_clock::now())
        {
            socket_.close();
            request_deadline_.expires_at((std::chrono::steady_clock::time_point::max)());
        }
        request_deadline_.async_wait(
            [this](beast::error_code)
            {
                check_deadline();
            });
    }
};

void api_handler_setup()
{
    getGlobalThreadPool();

    try
    {
        // Hardcoded server settings equivalent to:
        // ./mobile_handler 192.168.1.213 8444 ./async_http 100 block
        auto const address = net::ip::make_address("192.168.1.213");
        unsigned short port = 8444;
        std::string doc_root = "./async_http"; // Not used in our JSON example.
        int num_workers = 100;
        bool spin = false; // "block" mode

        net::io_context ioc{1};
        tcp::acceptor acceptor{ioc, {address, port}};

        std::list<http_worker> workers;
        for (int i = 0; i < num_workers; ++i)
        {
            workers.emplace_back(acceptor, doc_root);
            workers.back().start();
        }

        if (spin)
            for (;;) ioc.poll();
        else
            ioc.run();
    }
    catch (const std::exception& e)
    {
        std::cerr << "[ERROR] " << e.what() << std::endl;
        return ;
    }
    return;
}
