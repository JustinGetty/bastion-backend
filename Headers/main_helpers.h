//
// Created by root on 4/21/25.
//

#ifndef MAIN_HELPERS_H
#define MAIN_HELPERS_H
#include <iostream>
#include <bastion_data.h>

std::string generate_transaction_id();
STATUS verify_spa_and_get_site_id(std::string spa_id, int *site_id);

#endif //MAIN_HELPERS_H
