//
// Created by root on 4/7/25.
//

#include "UserCreation.h"
#include <bastion_data.h>
#include "cryptography.h"
#include "databaseq.h"
#include <openssl/rand.h>

STATUS create_new_user(bastion_username username, new_user_outbound_data* user_data) {

    /*
     *Here we need to do as follows:
     * Create auth token
     * Create auth token hash
     * Store auth token hash
     * Create asym keys, store the public one in a file and private one in the database
     * Create sym key and store it in a file
     * Encrypt auth token hash with sym key
     * Encrypt sym-encrypted auth token with public key
     * Encode this to a string
     * Encrypt sym ket with public key
     * Encode this to a string
     * Put those encode in the bash test file
     * Send that back as json
     * Decode it all and verify it works
     */



    //Create auth token ----------------------------------------------------------------
    token auth_token{};
    if (generate_token(auth_token, TOKEN_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Auth token generation failed.\n");
        return AUTH_TOKEN_GEN_FAILURE;
    }
    std::cout << "[INFO] New auth token generated.\n";

    //compute hash of token ----------------------------------------------------------------
    token_hash computed_hash{};
    compute_token_hash(auth_token, TOKEN_SIZE, computed_hash);
    std::printf("[INFO] Computed Token Hash.\n");

    //Store token hash ---------------------------------------------------------------------
    STATUS store_token_hash_stat = store_token_hash(1, computed_hash, TOKEN_SIZE);
    std::cout << "[INFO] Store token hash status: " << store_token_hash_stat << "\n";
    if (store_token_hash_stat != SUCCESS) {
        std::cout << "[ERROR] ERROR STORING HASH, EXITING\n";
        return DATABASE_FAILURE;
    }

    //create asym keys ----------------------------------------------------------------------
    asym_key_struct asym_keys{};
    if (generate_asym_keypair(&asym_keys) != SUCCESS) {
        std::cerr << "[ERROR] Failed to generate asymmetric key pair\n";
        return ASYM_KEY_GEN_FAILURE;
    }
    std::cout << "[INFO] Generated asymmetric key pair.\n";

    //store private key ----------------------------------------------------------------------
    priv_key_w_length priv_key_full{};
    memcpy(priv_key_full.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    priv_key_full.priv_key_len = asym_keys.priv_key_len;
    STATUS asym_priv_store_stat = store_user_private_key(1, &priv_key_full);
    if (asym_priv_store_stat != SUCCESS) {
        std::cerr << "[ERROR] Failed to store private key.\n";
        return DATABASE_FAILURE;
    }
    std::cout << "[INFO] Stored private key in database.\n";


    //Generate sym key and iv ------------------------------------------------------------------
    sym_key key{}; sym_iv iv{};
    if (generate_symmetric_key(key, KEY_SIZE) != SUCCESS) {
        std::fprintf(stderr, "[ERROR] Symmetric key generation failed\n");
        return SYM_KEY_GEN_FAILURE;
    }

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        std::fprintf(stderr, "[ERROR] IV generation failed\n");
        return SYM_KEY_GEN_FAILURE;
    }
    std::cout << "[INFO] Generated symmetric key.\n";


    /* TODO here need to test encrypt something with key then decrypt to ensure it works before going to PROD */
    /* later setup to send tokens over with data enc*/

    memcpy(user_data->new_username, username, sizeof(username));
    memcpy(user_data->new_raw_token, auth_token, sizeof(auth_token));
    memcpy(user_data->new_pub_key.pub_key, asym_keys.pub_key, sizeof(asym_keys.pub_key));
    user_data->new_pub_key.pub_key_len = asym_keys.pub_key_len;
    memcpy(user_data->new_sym_key.symmetric_iv, iv, sizeof(iv));
    memcpy(user_data->new_sym_key.symmetric_key, key, sizeof(key));

    return SUCCESS;
}

STATUS process_new_user_to_send(new_user_outbound_data* user_data, std::string* user_data_json) {

    return SUCCESS;
}
