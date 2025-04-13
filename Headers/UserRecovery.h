//
// Created by root on 4/10/25.
//
#ifndef USERRECOVERY_H
#define USERRECOVERY_H
#include <bastion_data.h>
#include <iostream>



STATUS recover_user_by_seed_phrase(bastion_username username, std::string seed_phrase, recovered_sec_user_outbound_data *outbound_data);
STATUS recover_user_by_email(bastion_username username);

#endif //USERRECOVERY_H
