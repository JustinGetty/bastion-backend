//
// Created by root on 5/20/25.
//

#include "EmailDAO.h"

#include <bastion_data.h>

EmailDAO::EmailDAO(sqlite3* db) : db(db) {

    if (sqlite3_prepare_v2(db, INSERT_NEW_USER_EMAIL, -1, &stmtInsertUserEmail, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
}

EmailDAO::~EmailDAO() {
    sqlite3_finalize(stmtInsertUserEmail);
}

void EmailDAO::insertNewUserEmail(const std::string* username,
    const std::string* email_raw,
    const std::string* email_hash,
    const std::string* client_spa_id) {
    sqlite3_reset(stmtInsertUserEmail);
    sqlite3_clear_bindings(stmtInsertUserEmail);
    //order is username, spa_id, hash, raw email
    if (sqlite3_bind_text(stmtInsertUserEmail, 1, username->c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind TEXT in statement: stmtInsertUserEmail\n";
    }
    if (sqlite3_bind_text(stmtInsertUserEmail, 2, client_spa_id->c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind TEXT in statement: stmtInsertUserEmail\n";
    }
    if (sqlite3_bind_text(stmtInsertUserEmail, 3, email_hash->c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind TEXT in statement: stmtInsertUserEmail\n";
    }

    if (sqlite3_bind_text(stmtInsertUserEmail, 4, email_raw->c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind TEXT in statement: stmtInsertUserEmail\n";
    }

    int step_result = sqlite3_step(stmtInsertUserEmail);
    if (step_result == SQLITE_DONE) {
        std::cout << "[INFO] User email addedd succesfully\n";
    } else {
        std::cerr << "[ERROR] Failed to add user email\n";
    }
}
