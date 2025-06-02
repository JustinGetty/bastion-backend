//
// Created by root on 4/21/25.
//

#include "../Headers/main_helpers.h"
#include <array>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include "databaseq.h"
#include <bastion_data.h>

#include "database_comm_v2.h"

std::string generate_transaction_id() {
    std::array<unsigned char, 16> bytes;

    //random_devide non-deterministic
    std::random_device rd;
    for (auto &b : bytes) {
        b = static_cast<unsigned char>(rd() & 0xFF);
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto b : bytes) {
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}

//TODO make sure when client registers on our site they create a spa id!!!
STATUS verify_spa_and_get_site_id(std::string spa_id, int *site_id) {
    STATUS client_id_status = get_site_id_by_spa_id_v2(&spa_id, site_id);
    if (client_id_status != SUCCESS) {
        std::cout << "[INFO] Client ID retrieval failed.\n";
        return DATABASE_FAILURE;
    }
    return SUCCESS;
}
