//
// Created by root on 4/7/25.
//

#include "../Headers/UserCreation.h"
#include <bastion_data.h>
#include "cryptography.h"
#include "databaseq.h"
#include <openssl/rand.h>
#include <iostream>
#include <string>
#include <sstream>

STATUS create_new_user(bastion_username username, new_user_outbound_data* user_data) {

    /*
     *Here we need to do as follows:
     */


    //need to create new user in DB

    //Create auth token ----------------------------------------------------------------
    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Auth token generation failed.\n");
        return AUTH_TOKEN_GEN_FAILURE;
    }
    std::cout << "[INFO] New auth token generated.\n";
    print_hex(auth_token, TOKEN_SIZE);

    //compute hash of token ----------------------------------------------------------------
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);
    std::printf("[INFO] Computed Token Hash.\n");


    //create asym keys ----------------------------------------------------------------------
    asym_key_struct asym_keys{};
    if (generate_asym_keypair(&asym_keys) != SUCCESS) {
        std::cerr << "[ERROR] Failed to generate asymmetric key pair\n";
        return ASYM_KEY_GEN_FAILURE;
    }
    std::cout << "[INFO] Generated asymmetric key pair.\n";
    print_hex(asym_keys.pub_key, asym_keys.pub_key_len);

    //store private key ----------------------------------------------------------------------
    priv_key_w_length priv_key_full{};
    memcpy(priv_key_full.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    priv_key_full.priv_key_len = asym_keys.priv_key_len;


    //Generate sym key and iv ------------------------------------------------------------------
    sym_key key{}; sym_iv iv{};
    if (generate_symmetric_key(key, KEY_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Symmetric key generation failed\n");
        return SYM_KEY_GEN_FAILURE;
    }
    std::cout << "[DEBUG] Sym key: \n";
    print_hex(key, KEY_SIZE);
    if (RAND_bytes(iv, IV_SIZE) != 1) {
        std::fprintf(stderr, "[ERROR] IV generation failed\n");
        return SYM_KEY_GEN_FAILURE;
    }
    std::cout << "[DEBUG] Sym iv: \n";
    print_hex(iv, IV_SIZE);

    std::cout << "[INFO] Generated symmetric key.\n";


    /* TODO here need to test encrypt something with key then decrypt to ensure it works before going to PROD */
    /* later setup to send tokens over with data enc*/

    //TODO DO NOT GO TO PROD WITH THIS PLEASEEEEEEEE
    username[MAX_USERNAME_LENGTH - 1] = '\0';
    new_user_struct new_user_data{};
    memcpy(new_user_data.new_username, username, sizeof(username));
    memcpy(new_user_data.new_token_hash, computed_hash, HASH_SIZE);
    memcpy(new_user_data.new_priv_key.priv_key, priv_key_full.priv_key, ASYM_SIZE);
    new_user_data.new_priv_key.priv_key_len = priv_key_full.priv_key_len;
    STATUS ins_to_db_stat = add_new_user_to_db(&new_user_data);
    if (ins_to_db_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to insert new user in database\n";
        return DATABASE_FAILURE;
    }
    std::cout << "[INFO] Added new user to database.\n";

    memcpy(user_data->new_username, username, sizeof(username));
    memcpy(user_data->new_raw_token, auth_token, sizeof(auth_token));
    memcpy(user_data->new_pub_key.pub_key, asym_keys.pub_key, sizeof(asym_keys.pub_key));
    user_data->new_pub_key.pub_key_len = asym_keys.pub_key_len;
    memcpy(user_data->new_sym_key.symmetric_iv, iv, sizeof(iv));
    memcpy(user_data->new_sym_key.symmetric_key, key, sizeof(key));


    return SUCCESS;
}

STATUS process_new_user_to_send(new_user_outbound_data* user_data, std::string* user_data_json) {

    std::string encoded_token = base64_encode(user_data->new_raw_token, TOKEN_SIZE);
    std::string username_temp= user_data->new_username;
    std::string encoded_username = base64_encode((const unsigned char *)user_data->new_username, username_temp.length());
    std::string encoded_pub_key = base64_encode(user_data->new_pub_key.pub_key, user_data->new_pub_key.pub_key_len);
    std::string encoded_sym_key = base64_encode(user_data->new_sym_key.symmetric_key, KEY_SIZE);
    std::string encoded_sym_iv = base64_encode(user_data->new_sym_key.symmetric_iv, IV_SIZE);

    //std::string resp = R"({"status": "valid"})";
    std::ostringstream oss;
    oss << "{\"status\": \"valid\", "
            << "\"token\": \"" << encoded_token << "\", "
            << "\"username\": \"" << encoded_username << "\", "
            << "\"pub_key\": \"" << encoded_pub_key << "\", "
            << "\"sym_key\": \"" << encoded_sym_key << "\", "
            << "\"sym_iv\": \"" << encoded_sym_iv << "\"}";
    std::string jsonString = oss.str();

    *user_data_json = oss.str();
    std::cout << "[INFO] Data being sent: " << *user_data_json << "\n";
    return SUCCESS;
}
