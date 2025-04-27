//
// Created by root on 4/27/25.
//

#include "ios_notifications.h"
#include <fstream>
#include <curl/curl.h>
#include <jwt/jwt.hpp>
#include <jwt/algorithm.hpp>
#include "databaseq.h"

std::string load_pem(const std::string& path) {
    std::ifstream in(path);
    return std::string((std::istreambuf_iterator<char>(in)),
                       std::istreambuf_iterator<char>());
}

//TODO put this on timer to remake every 45 minutes

std::string make_apns_jwt()
{
    auto key_pem = load_pem("AuthKey_ABCDE12345.p8");

    jwt::jwt_object obj{
        jwt::params::algorithm(jwt::algorithm::ES256),
        jwt::params::secret(key_pem)
    };

    obj.header().add_header("kid", "ABCDE12345");
    obj.payload().add_claim(jwt::registered_claims::issuer,     "YOUR_TEAM_ID");
    obj.payload().add_claim(jwt::registered_claims::issued_at,  std::chrono::system_clock::now());

    return obj.signature();
}

void send_push(const std::string& deviceToken,
               const std::string& jwt,
               const std::string& payloadJson)
{
    CURL* curl = curl_easy_init();
    if (!curl) return;

    std::string url = "https://api.push.apple.com/3/device/" + deviceToken;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers,
      ("authorization: bearer " + jwt).c_str());
    headers = curl_slist_append(headers,
      "apns-topic: com.mycompany.myapp");
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

void notify_signin_request(const std::string& username,
                           const std::string& siteName,
                           const std::string& siteUrl,
                           const std::string& requestId)
{
    // 1) load JWT (regenerate if expired)
    static std::string apnsJwt = make_apns_jwt();
    // TODO: check expiration and refresh every 45min

    std::string token;
    bastion_username username_temp{};
    strncpy(username_temp, username.c_str(), username.length());
    STATUS token_ret_status = get_device_token_by_username(&username_temp, &token);

    crow::json::wvalue aps;
    aps["alert"]["title"] = "Sign-in request";
    aps["alert"]["body"]  = siteName + " wants to sign you in";
    aps["category"]       = "SIGNIN_REQUEST";

    crow::json::wvalue top;
    top["aps"]         = aps;
    top["requestId"]   = requestId;
    top["siteName"]    = siteName;
    top["siteUrl"]     = siteUrl;
    top["type"]        = "authRequest";

    std::string payload = crow::json::dump(top);

    // 4) send it
    send_push(token, apnsJwt, payload);
}

