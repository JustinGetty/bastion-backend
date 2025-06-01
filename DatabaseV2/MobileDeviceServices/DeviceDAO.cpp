//
// Created by root on 5/20/25.
//

#include "DeviceDAO.h"

DeviceDAO::DeviceDAO(sqlite3 *db_) : db(db_)
{
    if (sqlite3_prepare_v2(db, UPDATE_DEVICE_TOKEN_IOS, -1, &stmtInsertApnsByUsername, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
}

DeviceDAO::~DeviceDAO() {
    sqlite3_finalize(stmtInsertApnsByUsername);
}

void DeviceDAO::insertOrUpdateToken(const std::string& uname, const ios_device_token& token) {
    sqlite3_reset(stmtInsertApnsByUsername);
    sqlite3_clear_bindings(stmtInsertApnsByUsername);

    std::cout << "[INFO] Binding Username: " << uname << "\n";

    if (sqlite3_bind_text(stmtInsertApnsByUsername, 1, uname.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind text for username.\n";
    }

    std::cout << "[INFO] Binding Device Token: " << token << "\n";

    if (sqlite3_bind_text(stmtInsertApnsByUsername, 2, token.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cout << "[ERROR] Failed to bind text for APNS TOKEN.\n";
    }

    const char *expanded = sqlite3_expanded_sql(stmtInsertApnsByUsername);
    if (expanded) {
        std::cout
          << "[DEBUG] Fully bound SQL:\n"
          << expanded
          << "\n";
        sqlite3_free((void*)expanded);
    } else {
        std::cout << "[DEBUG] sqlite3_expanded_sql() returned NULL\n";
    }

    int step_result = sqlite3_step(stmtInsertApnsByUsername);
    if (step_result == SQLITE_DONE) {
        std::cout << "[INFO] Device token added successfully\n";
    }
    else {
        std::cerr << "[ERROR] Failed to add APNS TOKEN for device.\n";
        std::cerr << "[ERROR] SQLite error [" << step_result << "]: "
              << sqlite3_errmsg(sqlite3_db_handle(stmtInsertApnsByUsername))
              << "\n";
    }

}

