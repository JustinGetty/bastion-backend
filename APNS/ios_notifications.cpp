//  ios_notifications.cpp
//  bastion-ios-mobile-server
//
// TODO do "validity check" and only send banner alert if valid; otherwise send silent push!!

#include "../Headers/ios_notifications.h"
#include <fstream>
#include <sstream>
#include <curl/curl.h>
#include <jwt/jwt.hpp>
#include <nlohmann/json.hpp>
#include "databaseq.h"

using json = nlohmann::json;

// ─────────────────────────────────────────────────────────────────────────────
//  Apple credentials & bundle identifier
// ─────────────────────────────────────────────────────────────────────────────
static constexpr char kAuthKeyPath[] = "/infinite/Projects/NoPass/Server/certs/AuthKey_DS6Q8VRAF7.p8";
static constexpr char kKeyId[]       = "DS6Q8VRAF7";
static constexpr char kTeamId[]      = "X8D485939U";
static constexpr char kBundleId[]    = "bastion-software.bastion-ios-mobile";

static std::string load_p8_key() {
    std::ifstream in(kAuthKeyPath, std::ios::binary);
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static const char* apns_host(bool sandbox) {
    return sandbox
      ? "https://api.development.push.apple.com"
      : "https://api.push.apple.com";
}

static std::string make_apns_jwt() {
    static std::string    cachedToken;
    static auto           expiresAt = std::chrono::system_clock::now();

    if (!cachedToken.empty() && std::chrono::system_clock::now() < expiresAt) {
        return cachedToken;
    }

    auto p8 = load_p8_key();
    jwt::jwt_object obj{
        jwt::params::algorithm(jwt::algorithm::ES256),
        jwt::params::secret(p8)
    };
    obj.header().add_header("kid", kKeyId);
    auto& pay = obj.payload();
    pay.add_claim(jwt::registered_claims::issuer,    kTeamId);
    pay.add_claim(jwt::registered_claims::issued_at, std::chrono::system_clock::now());

    cachedToken = obj.signature();
    expiresAt   = std::chrono::system_clock::now() + std::chrono::minutes(45);
    return cachedToken;
}

static bool send_push(
    const std::string& deviceToken,
    const std::string& jwt,
    const std::string& payloadJson,
    bool sandbox = true
) {
    // Always use alert push-type (priority 10)
    CURL* curl = curl_easy_init();
    if (!curl) return false;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(
      headers,
      ("authorization: bearer " + jwt).c_str()
    );
    headers = curl_slist_append(
      headers,
      ("apns-topic: " + std::string(kBundleId)).c_str()
    );
    headers = curl_slist_append(
      headers,
      "apns-push-type: alert"
    );
    headers = curl_slist_append(
      headers,
      "apns-priority: 10"
    );

    std::string url = std::string(apns_host(sandbox)) + "/3/device/" + deviceToken;
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_URL,            url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER,     headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,     payloadJson.c_str());

    CURLcode res = curl_easy_perform(curl);
    long statusCode = 0;
    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &statusCode);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return (res == CURLE_OK && statusCode >= 200 && statusCode < 300);
}

STATUS notify_signin_request(
    const std::string& username,
    const std::string& siteName,
    const std::string& siteUrl,
    const std::string& requestId
) {
    apns_token tokenBuf{};
    bastion_username uname{};
    strncpy(uname, username.c_str(), sizeof(uname)-1);
    uname[sizeof(uname)-1] = '\0';

    if (get_device_token_by_username(&uname, &tokenBuf) != SUCCESS) {
        std::cerr << "[ERROR] Could not load device token for " << username << "\n";
        return DATABASE_FAILURE;
    }
    std::string deviceToken(reinterpret_cast<char*>(tokenBuf));
    auto jwt = make_apns_jwt();

    // Build a single payload with both alert and content‑available
    nlohmann::json aps = {
        { "alert", {
            { "title", siteName + " wants to sign you in" },
            { "body",  "Authorize sign‑in" }
        }},
        { "sound",            "default" },
        { "badge",               1 },
        { "category",   "SIGNIN_REQUEST" },
        { "content-available",   1 }
    };

    nlohmann::json payload = {
        { "aps",       aps },
        { "requestId", requestId },
        { "siteId",    "demo_site_id" },
        { "siteName",  siteName },
        { "siteUrl",   siteUrl },
        { "type",      "authRequest" }
    };
    return send_push(deviceToken, jwt, payload.dump(), /*sandbox=*/true)
         ? SUCCESS
         : HTTP_FAILURE;
}
