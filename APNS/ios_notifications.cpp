//
// Created by root on 4/27/25.
//

#include "../Headers/ios_notifications.h"
#include <fstream>
#include <curl/curl.h>
#include <jwt/jwt.hpp>
#include <jwt/algorithm.hpp>
#include "databaseq.h"
#include <nlohmann/json.hpp>

using json = nlohmann::json;

std::string load_pem(const std::string& path) {
    std::ifstream in(path);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

//TODO put this on timer to remake every 45 minutes

std::string make_apns_jwt()
{
    auto key_pem = load_pem("/infinite/Projects/NoPass/Server/certs/AuthKey_DS6Q8VRAF7.p8");

    jwt::jwt_object obj{
        jwt::params::algorithm(jwt::algorithm::ES256),
        jwt::params::secret(key_pem)
    };

    obj.header().add_header("kid", "DS6Q8VRAF7");
    obj.payload().add_claim(jwt::registered_claims::issuer, "X8D485939U");
    obj.payload().add_claim(jwt::registered_claims::issued_at,  std::chrono::system_clock::now());

    return obj.signature();
}

void send_push(const std::string& deviceToken,
               const std::string& jwt,
               const std::string& payloadJson)
{
    CURL* curl = curl_easy_init();
    if (!curl) return;

    std::string url = "https://api.development.push.apple.com/3/device/" + deviceToken;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers,
      ("authorization: bearer " + jwt).c_str());
    headers = curl_slist_append(headers,
      "apns-topic: bastion-software.bastion-ios-mobile");
    headers = curl_slist_append(headers,
      "apns-push-type: alert");

    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payloadJson.c_str());

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK)
        fprintf(stderr, "APNs send error: %s\n", curl_easy_strerror(res));

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

STATUS notify_signin_request(const std::string& username,
                           const std::string& siteName,
                           const std::string& siteUrl,
                           const std::string& requestId)
{
    // 1) load JWT (regenerate if expired)
    static std::string apnsJwt = make_apns_jwt();
    // TODO: check expiration and refresh every 45min

    apns_token token;
    bastion_username username_temp{};
    strncpy(username_temp, username.c_str(), sizeof(username_temp)-1);
    username_temp[sizeof(username_temp)-1] = '\0';

    STATUS token_ret_status = get_device_token_by_username(&username_temp, &token);
    std::string token_string(reinterpret_cast<const char*>(token), 32);
    if (token_ret_status != SUCCESS) {
        std::cout << "[INFO] Failed to get device token, sign in request aborted\n";
        return DATABASE_FAILURE;
    }

    json aps = {
      { "alert", {
          { "title", "Sign-in request" },
          { "body",  siteName + " wants to sign you in" }
        }
      },
      { "category", "SIGNIN_REQUEST" }
    };

    // 2) Build the top-level payload
    json payloadJson = {
      { "aps",       aps },
      { "requestId", requestId },
      { "siteName",  siteName },
      { "siteUrl",   siteUrl },
      { "type",      "authRequest" }
    };

    std::string payload = payloadJson.dump();  // compact by default


    send_push(token_string, apnsJwt, payload);
    return SUCCESS;
}

