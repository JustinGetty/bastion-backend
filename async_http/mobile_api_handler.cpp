#include "../Headers/mobile_api_handler.h"
#include "../Headers/conn_data_storage.h"
#include "../Headers/parse_message_json.h"
#include "../Headers/cryptography.h"

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

namespace beast = boost::beast;         // from <boost/beast.hpp>
namespace http = beast::http;           // from <boost/beast/http.hpp>
namespace net = boost::asio;            // from <boost/asio.hpp>
using tcp = boost::asio::ip::tcp;       // from <boost/asio/ip/tcp.hpp>

/*TODO
 *pickup here
 *seperate thread work in different way, link files like usual
 */


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

    // Read an HTTP request from the socket.
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

    // Process the HTTP request.
    void process_request(http::request<request_body_t, http::basic_fields<alloc_t>> const& req)
    {

        //get requests
        if(req.method() == http::verb::get)
        {
            //likely never using get, since apple notif will be post to apple ANS server and then post back here
            send_json_response("{\"message\":\"Hello from GET\"}", http::status::ok);
        }
        //post requests
        /*
         *READ BACK THE users's sign in details and keys
         *notif to user sent in different thread with APPLE/ANDROID notif services
         */
        else if(req.method() == http::verb::post)
        {
            std::string received_json = req.body();
            std::cout << "Data Received: " << received_json << std::endl;
            //std::string response_json = "{\"received\": " + received_json + "}";

            MsgMethod msg_method;
            try {
                msg_method = parse_method(received_json);
                std::cout << "Method type: " << msg_method.type << std::endl;
                for (const auto &kv : msg_method.keys)
                    std::cout << kv.first << " : " << kv.second << std::endl;
            } catch (const std::exception &ex) {
                std::cerr << "Error: " << ex.what() << "\n";
            }

            /*
             *From here keys and data gets added to thread pool queue for processing
             */

            auto temp_val = msg_method.keys.find("client_auth_token_enc");
            std::string token_hash_encoded;
            if (temp_val != msg_method.keys.end()) {
                token_hash_encoded = temp_val->second;
                std::cout << "Auth token: " << token_hash_encoded << std::endl;

            } else {
                std::cout << "Auth token not found" << std::endl;
                return;
            }

            temp_val = msg_method.keys.find("sym_key_enc");
            std::string sym_key_enc;
            if (temp_val != msg_method.keys.end()) {
                sym_key_enc = temp_val->second;
                std::cout << "sym key: " << sym_key_enc << std::endl;

            } else {
                std::cout << "Sym key not found" << std::endl;
                return;
            }

            temp_val = msg_method.keys.find("connection_id");
            int connection_id;
            if (temp_val != msg_method.keys.end()) {
                connection_id = std::stoi(temp_val->second);
                std::cout << "Connection ID: " << connection_id << std::endl;
            } else {
                std::cout << "Connection ID not found" << std::endl;
                return;
            }

            //error handle here if theyre not found!!

            //create validation work object and add it to the queue to be executed
            //TODO need to get the connection data out of conn_data_queue that will have the asym key

            //id_(id), user_id(user_id), token_hash_encoded(token_hash_encoded), sym_key_iv_encoded(sym_key_iv_encoded)
            //ID needs to be random or systematic idk
            g_workQueue.push(new MyValidationWork(connection_id, 1, token_hash_encoded, sym_key_enc));


            //send back status response to mobile
            send_json_response(received_json, http::status::ok);
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
        std::cerr << "Error: " << e.what() << std::endl;
        return ;
    }
    return;
}

/*
unsigned char keyData[] = { 0x01, 0x02, 0x03, 0x04, 0x05 };
    size_t keyLength = sizeof(keyData);

    // 1. Encode the binary key into a Base64 string.
    std::string encodedKey = base64_encode(keyData, keyLength);
    std::cout << "Encoded Key: " << encodedKey << std::endl;

    // 2. Construct a JSON object containing the encoded key.
    nlohmann::json j;
    j["key"] = encodedKey;
    std::string jsonString = j.dump();
    std::cout << "JSON Payload: " << jsonString << std::endl;

    // 3. Later, parse the JSON and decode the Base64 string back to binary.
    nlohmann::json parsed = nlohmann::json::parse(jsonString);
    std::string encodedKeyFromJson = parsed["key"];
    std::vector<unsigned char> decodedKey = base64_decode(encodedKeyFromJson);

    // 4. Print the decoded binary key in hexadecimal format.
    std::cout << "Decoded Binary Key: ";
    for (unsigned char byte : decodedKey) {
        printf("%02x", byte);
    }
    std::cout << std::endl;
    */

