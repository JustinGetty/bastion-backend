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
#include "SeedCipher.h"
#include "database_comm_v2.h"

STATUS create_new_user_unsec(std::string* username, new_user_outbound_data* user_data) {
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
    memcpy(new_user_data.new_username, username->c_str(), username->length());
    memcpy(new_user_data.new_token_hash, computed_hash, HASH_SIZE);
    memcpy(new_user_data.new_priv_key.priv_key, priv_key_full.priv_key, ASYM_SIZE);
    new_user_data.new_priv_key.priv_key_len = priv_key_full.priv_key_len;
    //STATUS ins_to_db_stat = add_new_user_to_db(&new_user_data);
    STATUS ins_to_db_stat = add_new_user_to_db_v2(&new_user_data);
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

/*
 *Important differentiation is that here we need to encrypt the auth token hash and regular with the key (store iv + X)
 *this way the raw token is recoverable given seed phrase (regen same keys, still have the token server side)
 */

STATUS create_new_user_sec(bastion_username username, new_user_outbound_data* user_data) {

    /*Plan
     * create token, hash, etc.
     * encrypt token in DB with sym
     * use asym keys to end2end encrypt
     * if raw token ever needed, seed phrase will regen keys, decryot token, send token, restart
     * dont need sym key to ever be sent in this flow
     */

    //Create auth token ----------------------------------------------------------------
    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Auth token generation failed.\n");
        return AUTH_TOKEN_GEN_FAILURE;
    }
    std::cout << "[INFO] New auth token generated.\n";
    print_hex(auth_token, TOKEN_SIZE);

    //STORE THIS IN DB AFTER ENCRYPTING WITH CIPHERSEED TODO
    /*--------------------------------------------------------------------------*/
    SeedCipher cipher(12);

    // Generate a seed phrase and display it.
    cipher.generateSeedPhrase();
    std::string seed = cipher.getSeedPhrase();
    std::cout << "Generated Seed Phrase: " << seed << std::endl;

    // Derive the symmetric key and display it in hex.
    cipher.deriveKey();
    std::string keyHex = cipher.getKeyHex();
    std::cout << "Derived Key (hex): " << keyHex << std::endl;

    token_sec raw_token_encrypted{};
    cipher.encryptToken(auth_token, raw_token_encrypted);

    token token_out{};
    cipher.decryptToken(raw_token_encrypted, token_out);

    // Verify that the decrypted binary data matches the original.
    if (memcmp(&auth_token, &token_out, sizeof(auth_token)) == 0) {
        std::cout << "Success: Binary data matches original." << std::endl;
    } else {
        std::cout << "Error: Binary data does not match." << std::endl;
        return CRYPTO_FAILURE;
    }
    /*--------------------------------------------------------------------------*/


    //TODO destruct the SeedCipher object


    //compute hash of token ----------------------------------------------------------------
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);
    std::printf("[INFO] Computed Token Hash.\n");


    //compute hash of seed phrase -----------------------------------------------------------
    seed_phrase_hash seed_phrase{};
    int seed_phrase_length = seed.size();
    compute_seed_phrase_hash(seed, seed_phrase_length, seed_phrase);
    std::printf("[INFO] Computed Seed Phrase Hash.\n");
    print_hex(seed_phrase, std::size(seed_phrase));


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



    /* TODO here need to test encrypt something with key then decrypt to ensure it works before going to PROD */
    /* later setup to send tokens over with data enc*/

    //TODO DO NOT GO TO PROD WITH THIS PLEASEEEEEEEE
    username[MAX_USERNAME_LENGTH - 1] = '\0';
    new_user_struct_sec new_user_data{};


    memcpy(new_user_data.new_username, username, MAX_USERNAME_LENGTH);
    memcpy(new_user_data.new_token_hash, computed_hash, HASH_SIZE);
    //fix
    memcpy(new_user_data.new_token_encrypted, raw_token_encrypted, 64);
    memcpy(new_user_data.new_priv_key.priv_key, priv_key_full.priv_key, ASYM_SIZE);
    new_user_data.new_priv_key.priv_key_len = priv_key_full.priv_key_len;
    memcpy(new_user_data.seed_phrase, seed_phrase, 64);
    //STATUS ins_to_db_stat = add_new_sec_user_to_db(&new_user_data);
    STATUS ins_to_db_stat = add_new_sec_user_to_db_v2(&new_user_data);
    if (ins_to_db_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to insert new user in database\n";
        return DATABASE_FAILURE;
    }
    std::cout << "[INFO] Added new user to database.\n";

    memcpy(user_data->new_username, username, MAX_USERNAME_LENGTH);
    memcpy(user_data->new_raw_token, auth_token, sizeof(auth_token));
    memcpy(user_data->new_pub_key.pub_key, asym_keys.pub_key, sizeof(asym_keys.pub_key));
    user_data->new_pub_key.pub_key_len = asym_keys.pub_key_len;
    user_data->seed_phrase = seed;


    return SUCCESS;
}






STATUS process_new_user_to_send(new_user_outbound_data* user_data, std::string* user_data_json) {
    std::string encoded_token = base64_encode(user_data->new_raw_token, TOKEN_SIZE);
    std::string username_temp= user_data->new_username;
    std::string encoded_username = base64_encode((const unsigned char *)user_data->new_username, username_temp.length());
    std::string encoded_pub_key = base64_encode(user_data->new_pub_key.pub_key, user_data->new_pub_key.pub_key_len);
    std::string encoded_sym_key = base64_encode(user_data->new_sym_key.symmetric_key, KEY_SIZE);
    std::string encoded_sym_iv = base64_encode(user_data->new_sym_key.symmetric_iv, IV_SIZE);

    if (user_data->secure_type == false) {

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




    if (user_data->secure_type == true) {

        //std::string resp = R"({"status": "valid"})";
        std::ostringstream oss;
        oss << "{\"status\": \"valid\", "
                << "\"token\": \"" << encoded_token << "\", "
                << "\"username\": \"" << encoded_username << "\", "
                << "\"pub_key\": \"" << encoded_pub_key << "\", "
                << "\"seed_phrase\": \"" << user_data->seed_phrase << "\"}";
        std::string jsonString = oss.str();

        *user_data_json = oss.str();
        std::cout << "[INFO] Data being sent: " << *user_data_json << "\n";
        return SUCCESS;
    }

    return LOGIC_FAILURE;
}
