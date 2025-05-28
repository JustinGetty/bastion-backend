//
// Created by root on 4/10/25.
//

#include "../Headers/UserRecovery.h"
#include "cryptography.h"
#include <bastion_data.h>
#include "databaseq.h"
#include "SeedCipher.h"
#include <sstream>
#include "database_comm_v2.h"

//TODO need to standardize seed phrase!!!
STATUS recover_user_by_seed_phrase(bastion_username username, std::string seed_phrase, recovered_sec_user_outbound_data *outbound_data) {
    bastion_username uname_local{};
    memcpy(uname_local, username, sizeof(username));
    STATUS verification_status = verify_seed_phrase(username, seed_phrase);
    if (verification_status != SUCCESS) {
        std::cout << "[INFO] Verificaiton of seed phrase failed.\n";
        return CRYPTO_FAILURE;
    }

    //ok the phrase matches, just "create" new user, literally creater new user but set seed phrase instead of gen

   /* Recovery Flow
    * This flow is slightly different, do not regen auth token, need to get encrypted raw token from db,
    * decrypt with new derived keys,
    * then we will send to user.
    * STRUCTURE
    * get auth token enc
    * decrypt
    * send to user
    * create asym keys, update priv key in db
    * make sure on mobile you let user know to keep track of their seed phrase
    */


    SeedCipher seed_cipher{};
    seed_cipher.setSeedPhrase(seed_phrase);
    seed_cipher.deriveKey();

    token_sec token_enc{};
    STATUS ret_enc_token_status = get_sym_enc_auth_token(&uname_local, &token_enc);
    if (ret_enc_token_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to get user token enc\n";
        return DATABASE_FAILURE;
    }

    //fix
    token raw_token{};
    seed_cipher.decryptToken(token_enc, raw_token);

    //so far we have raw_auth token to send
    //recovered sym key
    //need to just regen asym and store priv/send pub and we are chill tipping

    asym_key_struct asym_keys{};
    STATUS key_gen_status = generate_asym_keypair(&asym_keys);
    if (key_gen_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to generate keys\n";
        return ASYM_KEY_GEN_FAILURE;
    }
    priv_key_w_length private_key{};
    memcpy(private_key.priv_key, asym_keys.priv_key, asym_keys.priv_key_len);
    private_key.priv_key_len = asym_keys.priv_key_len;

    //STATUS store_priv_key_status = store_user_priv_key_by_username(username_ptr, private_key);
    std::string uname_str(uname_local);
    STATUS store_priv_key_status = store_user_priv_key_by_username_v2(&uname_str, &private_key);

    if (store_priv_key_status != SUCCESS) {
        std::cerr << "Failed to store user private key";
        return DATABASE_FAILURE;
    }

    //seg fault
    memcpy(outbound_data->auth_token_raw, raw_token, 32);
    memcpy(outbound_data->pub_key.pub_key, asym_keys.pub_key, asym_keys.pub_key_len);
    outbound_data->pub_key.pub_key_len = asym_keys.pub_key_len;

    return SUCCESS;
}

STATUS process_sec_recover_to_send(recovered_sec_user_outbound_data *outbound_data, std::string *outbound_response) {
    std::string encoded_token = base64_encode(outbound_data->auth_token_raw, TOKEN_SIZE);
    std::string encoded_pub_key = base64_encode(outbound_data->pub_key.pub_key, outbound_data->pub_key.pub_key_len);


    //std::string resp = R"({"status": "valid"})";
    std::ostringstream oss;
    oss << "{\"status\": \"valid\", "
            << "\"token\": \"" << encoded_token << "\", "
            << "\"pub_key\": \"" << encoded_pub_key << "\"}";

    *outbound_response = oss.str();
    std::cout << "[INFO] Data being sent: " << outbound_response << "\n";
    return SUCCESS;
}
