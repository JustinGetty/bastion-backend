//
// Created by root on 4/14/25.
//

#include "../Headers/EmailRecovery.h"
#include <bastion_data.h>


EmailRecovery::EmailRecovery() {
    //tbd
}
EmailRecovery::~EmailRecovery() {
    //tbd
}
void EmailRecovery::add_user_recovery_code(std::string username, int recovey_code) {
    user_recovery_codes[username] = recovey_code;
}
void EmailRecovery::remove_user_recovery_code(std::string username) {
    user_recovery_codes.erase(username);
}
int EmailRecovery::get_user_recovery_code(std::string username) {
    return user_recovery_codes[username];
}

STATUS EmailRecovery::validate_code(std::string username, int given_code) {
    int recovery_code = user_recovery_codes[username];
    if (recovery_code != given_code) {
        std::cout << "[INFO] Verification codes did not match.";
        user_recovery_codes.erase(username);
        return LOGIC_FAILURE;
    }

    user_recovery_codes.erase(username);
    return SUCCESS;
}


