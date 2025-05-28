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
#include "database_comm_v2.h"
#include "EmailSys.h"
#include "apiHandlerBoostPool.h"
#include "handler_functionality.h"





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

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

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

//TODO break these endpoints into smaller functions, just pass the json into a helper
//TODO optimize, STOP BLOCKING THE FUCKING EVENT LOOP. pass to thread pool for work intensive asks for shit like mobile get-site-data
//note boost::asio has built in threadpool
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
    apiHandlerBoostPool boost_thread_pool{ 3 };

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

    //helper for the endpoints. simply calls the helper function and then returns the json response, sends it, and then final return
    template<typename Helper>
    void dispatch_async(
        std::string query,
        Helper&& helper,
        http::status status = http::status::ok)
        {
            auto ioc = socket_.get_executor();

            boost_thread_pool.enqueue([
                this,
                ioc,
                query = std::move(query),
                helper = std::forward<Helper>(helper),
                status
            ]() mutable {
                std::string body = helper(query);

                boost::asio::post(ioc, [
                    this,
                    body = std::move(body),
                    status
                ]() mutable {
                    send_json_response(body, status);
                });
            });
        }

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
        if(req.method() == http::verb::get) {
            std::string targetStr = std::string(req.target());
            // Split into the path and query parts
            size_t pos = targetStr.find('?');
            std::string path = (pos != std::string::npos) ? targetStr.substr(0, pos) : targetStr;
            std::string query = (pos != std::string::npos) ? targetStr.substr(pos + 1) : "";

            if (path == "/get_site_data") {
                dispatch_async(query, [this](const std::string& q) {return get_site_data_helper(q);});
                return;
            }
            if (path == "/email_verif") {
                dispatch_async(query, [this](const std::string& q) {return verify_email_helper(q);});
                return;
            }
            if (path == "/secure_key") {
                dispatch_async(query, [this](const std::string& q) {return secure_key_helper(q);});
                return;
            }
            if (path == "/reg_keys") {
                dispatch_async(query, [this](const std::string& q) {return regular_key_helper(q);});
                return;
            }
            if (path == "/rec_by_seed") {
                dispatch_async(query, [this](const std::string& q) {return recover_by_seed_helper(q);});
                return;
            }
            if (path == "/rec_by_code") {
                /* SEE TODO AT TOP
                 * Requires username and code from email
                 */
                return;
            }
            if (path == "/") {
                std::cerr << "[ERROR] No endpoint specified\n";
                std::string resp = R"({"status":"ERROR_NO_ENDPOINT"})";
                send_json_response(resp, http::status::ok);
                return;
            }

            std::cerr << "[ERROR] Endpoint not found\n";
        } //end get requests


        else if(req.method() == http::verb::post) {

            std::string target = std::string(req.target());
            std::cout << "[INFO] Target: " << target << "\n";

            if (target == "/signinresponse") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return signin_response_helper(q);});
                return;
            }
            if (target == "/signupresponse") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return signup_response_helper(q);});
                return;
            }
            if (target == "/devices") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return device_token_helper(q);});
                return;
            }
            if (target == "/get_recovery_code") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return recovery_code_helper(q);});
                return;
            }
            if (target == "/validate_username") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return validate_username_helper(q);});
                return;
            }
            if (target == "/verify_code") {
                dispatch_async(std::string(req.body()), [this](const std::string& q) {return verify_code_helper(q);});
                return;
            }

           std::cerr << "[ERROR] Target likely not found (or endpoint missing a return statement).\n";
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
    //TODO replace old one with this one eventially
    /*
    void send_json_response(
        boost::asio::ip::tcp::socket& socket,
        http::request<http::string_body> const& req,
        std::string const& body,
        http::status status = http::status::ok)
        {
            // 1) Build the response
            http::response<http::string_body> res{status, req.version()};
            res.set(http::field::server, "bastion_auth");
            res.set(http::field::content_type, "application/json");
            res.keep_alive(req.keep_alive());
            res.body() = body;

            // 2) This sets the Content-Length header for you
            res.prepare_payload();

            // 3) And this writes it all in one call
            boost::system::error_code ec;
            http::write(socket, res, ec);
            if(ec)
                std::cerr << "[ERROR] HTTP write: " << ec.message() << "\n";
        }
        */


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
    //validation work queue
    getGlobalThreadPool();
    //blocking IO work goes here

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
