//
// Created by root on 4/10/25.
//

#include "../Headers/UserRecovery.h"
#include "cryptography.h"

//TODO need to standardize seed phrase!!!
STATUS recover_user_by_seed_phrase(bastion_username username, std::string seed_phrase) {

    STATUS verification_status = verify_seed_phrase(username, seed_phrase);
    if (verification_status != SUCCESS) {
        std::cout << "[INFO] Verificaiton of seed phrase failed.\n";
        return CRYPTO_FAILURE;
    }

    //ok the phrase matches, just "create" new user, literally creater new user but set seed phrase instead of gen



}
