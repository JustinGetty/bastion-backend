//
// Created by root on 5/19/25.
//

#include "UserDAO.h"
#include <bastion_data.h>

UserDAO::UserDAO(sqlite3* _db): db(_db) {
    //const char* SQL = "SELECT id, username FROM user WHERE id = ?";
    /*
    if (sqlite3_prepare_v2(db, SQL, -1, &stmtFindById, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
        */

    if (sqlite3_prepare_v2(db, GET_FULL_USER_DATA_BY_UNAME_QUERY, -1, &stmtFindByUsername, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
}

UserDAO::~UserDAO() {
    sqlite3_finalize(stmtFindByUsername);
}


full_user_data UserDAO::get_user_by_uname(std::string username) {
    sqlite3_reset(stmtFindByUsername);
    sqlite3_clear_bindings(stmtFindByUsername);
    if (sqlite3_bind_text(stmtFindByUsername, 1, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "AHHH ERROR BINDING AHHHH\n";
    }
    sqlite3_bind_text(stmtFindByUsername, 2, username.c_str(), -1, SQLITE_TRANSIENT);

    const char *expanded = sqlite3_expanded_sql(stmtFindByUsername);
    if (expanded) {
        std::cout
          << "[DEBUG] Fully bound SQL:\n"
          << expanded
          << "\n";
        sqlite3_free((void*)expanded);
    } else {
        std::cout << "[DEBUG] sqlite3_expanded_sql() returned NULL—"
                  << "are you using SQLite >= 3.14?\n";
    }

    full_user_data user_data{};

    if (sqlite3_step(stmtFindByUsername) == SQLITE_ROW) {
        user_data.user_id = sqlite3_column_int(stmtFindByUsername, 0);
        const unsigned char* raw_username = sqlite3_column_text(stmtFindByUsername, 1);
        if (raw_username != NULL) {
            strncpy(user_data.username, (const char*)raw_username, MAX_USERNAME_LENGTH - 1);
            user_data.username[MAX_USERNAME_LENGTH - 1] = '\0';
        } else {
            user_data.username[0] = '\0';
        }
        user_data.user_creation_time = sqlite3_column_int(stmtFindByUsername, 2);
        const unsigned char* raw_auth = (const unsigned char*)sqlite3_column_blob(stmtFindByUsername, 3);
        if (raw_auth != NULL) {
            memcpy(user_data.enc_auth_token, raw_auth, sizeof(user_data.enc_auth_token));
        }
        const unsigned char* raw_asym_key = (const unsigned char*)sqlite3_column_blob(stmtFindByUsername, 4);
        const int asym_key_len = sqlite3_column_int(stmtFindByUsername, 5);
        if (raw_asym_key != NULL) {
            memcpy(user_data.priv_key_w_len.priv_key, raw_asym_key, sizeof(user_data.priv_key_w_len.priv_key));
            user_data.priv_key_w_len.priv_key_len = asym_key_len;
        }

        const char *table_source = (const char*)sqlite3_column_text(stmtFindByUsername, 6);
        if (table_source && strcmp(table_source, "user_sec") == 0) {
            user_data.secure_recovery_method = true;
        } else {
            user_data.secure_recovery_method = false;
        }
    }

    printf("[DEBUG] Data retrieved:\n");
    printf("[DEBUG] User ID: %d\n", user_data.user_id);
    printf("[DEBUG] Username: %s\n", user_data.username);
    printf("[DEBUG] User creation time: %d\n", user_data.user_creation_time);

    return user_data;
}
