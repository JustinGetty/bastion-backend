//
// Created by root on 5/19/25.
//

#include "UserDAO.h"
#include <bastion_data.h>


/*NOTES
 * I am too lazy to make a new DAO for every type, so for now User is going to encompass alot of different types lmao
 */
UserDAO::UserDAO(sqlite3* _db): db(_db) {
    //const char* SQL = "SELECT id, username FROM user WHERE id = ?";
    /*
    if (sqlite3_prepare_v2(db, SQL, -1, &stmtFindById, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
        */

    if (sqlite3_prepare_v2(db, GET_FULL_USER_DATA_BY_UNAME_QUERY, -1, &stmtFindByUsername, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, CHECK_IF_USER_EXISTS_FOR_SITE, -1, &stmtCheckUserSiteExists, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, GET_SITE_DATA_FOR_MOBILE, -1, &stmtGetSiteData, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, UPDATE_SITE_USAGE, -1, &stmtUpdateSiteUsage, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, UPDATE_LAST_USED_SITE_TIMESTAMP, -1, &stmtUpdateLastSiteUsage, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, CREATE_USER_QUERY_REG, -1, &stmtInsertRegUser, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, CREATE_USER_QUERY_SEC, -1, &stmtInsertSecUser, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, UPDATE_USER_PRIV_KEY_BY_USERNAME, -1, &stmtInsertPrivKey, nullptr) != SQLITE_OK
        )
        //did you remember to finalize it?
        throw std::runtime_error("Failed to prepare statement");
}

UserDAO::~UserDAO() {
    sqlite3_finalize(stmtFindByUsername);
    sqlite3_finalize(stmtCheckUserSiteExists);
    sqlite3_finalize(stmtGetSiteData);
    sqlite3_finalize(stmtUpdateSiteUsage);
    sqlite3_finalize(stmtUpdateLastSiteUsage);
    sqlite3_finalize(stmtInsertRegUser);
    sqlite3_finalize(stmtInsertSecUser);
    sqlite3_finalize(stmtInsertPrivKey);
}


full_user_data UserDAO::findByUsername(const std::string& uname) {
    sqlite3_reset(stmtFindByUsername);
    sqlite3_clear_bindings(stmtFindByUsername);
    if (sqlite3_bind_text(stmtFindByUsername, 1, uname.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "AHHH ERROR BINDING AHHHH\n";
    }
    sqlite3_bind_text(stmtFindByUsername, 2, uname.c_str(), -1, SQLITE_TRANSIENT);

    const char *expanded = sqlite3_expanded_sql(stmtFindByUsername);
    if (expanded) {
        std::cout
          << "[DEBUG] Fully bound SQL:\n"
          << expanded
          << "\n";
        sqlite3_free((void*)expanded);
    } else {
        std::cout << "[DEBUG] sqlite3_expanded_sql() returned NULL\n";
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
    //printf("[DEBUG] User creation time: %d\n", user_data.user_creation_time);

    return user_data;
}

full_user_data UserDAO::findById(int id) {
    //implement later
    full_user_data user_data{};
    return user_data;
}

void UserDAO::insertNewUser(const full_user_data& u) {
    //impleement laterrr
   return;
}
void UserDAO::updateAuthToken(int userId, const token_hash& newHash) {
    //implement later
    return;
}

bool UserDAO::getUserSiteDataExists(const std::string username) {
    sqlite3_reset(stmtCheckUserSiteExists);
    sqlite3_clear_bindings(stmtCheckUserSiteExists);

    if (sqlite3_bind_text(stmtCheckUserSiteExists, 1, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind username for statement: stmtCheckUserSiteExists\n";
    }

    if (sqlite3_step(stmtCheckUserSiteExists) != SQLITE_ROW) {
        std::cout << "[INFO] User does not exist in site\n";
        return false;
    }
    std::cout << "[INFO] User does exist in site\n";
    return true;

}

//TODO move this to DeviceDAO
std::vector<site_data_for_mobile> UserDAO::getSiteDataForMobileUser(std::string username) {
    sqlite3_reset(stmtGetSiteData);
    sqlite3_clear_bindings(stmtGetSiteData);

    if (sqlite3_bind_text(stmtGetSiteData, 1, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind username for statement: stmtGetSiteData\n";
    }

    std::vector<site_data_for_mobile> outbound_data_local;
    while (sqlite3_step(stmtGetSiteData) == SQLITE_ROW) {

        const unsigned char* site_name_raw = sqlite3_column_text(stmtGetSiteData, 1);
        const unsigned char* site_domain_raw = sqlite3_column_text(stmtGetSiteData, 2);
        const unsigned char* user_email_raw = sqlite3_column_text(stmtGetSiteData, 3);

        outbound_data_local.emplace_back(
            (sqlite3_column_int(stmtGetSiteData, 0)),
            (site_name_raw ? reinterpret_cast<const char*>(site_name_raw) : std::string()),
            (site_domain_raw ? reinterpret_cast<const char*>(site_domain_raw) : std::string()),
            (user_email_raw ? reinterpret_cast<const char*>(user_email_raw) : std::string()),
            (sqlite3_column_int(stmtGetSiteData, 4)),
            (sqlite3_column_int64(stmtGetSiteData, 5)),
            (sqlite3_column_int64(stmtGetSiteData, 6))
            );
    }

    return outbound_data_local;
}


//TODO move this to site DAO
void UserDAO::updateSiteUsage(const std::string spa_id) {
    sqlite3_reset(stmtUpdateSiteUsage);
    sqlite3_clear_bindings(stmtUpdateSiteUsage);

   if (sqlite3_bind_text(stmtUpdateSiteUsage, 1, spa_id.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK) {
        std::cerr << "[ERROR] Failed to bind username for statement: stmtUpdateSiteUsage\n";
        return;
   }

    if (sqlite3_step(stmtUpdateSiteUsage) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to update site usage\n";
    }


}

void UserDAO::updateLastUserSiteUsage(const std::string username, const std::string spa_id) {
    sqlite3_reset(stmtUpdateLastSiteUsage);
    sqlite3_clear_bindings(stmtUpdateLastSiteUsage);

    std::cout << "[INFO] Updating last site usage\n";

   if (sqlite3_bind_text(stmtUpdateLastSiteUsage, 1, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
       || sqlite3_bind_text(stmtUpdateLastSiteUsage, 2, spa_id.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK)
       std::cerr << "Failed to bind username or spa id for statement: stmtUpdateLastSiteUsage\n";

    if (sqlite3_step(stmtUpdateLastSiteUsage) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to update last user site usage\n";
    }
}


void UserDAO::insertNewRegularUser(new_user_struct user_data) {
    sqlite3_reset(stmtInsertRegUser);
    sqlite3_clear_bindings(stmtInsertRegUser);

    std::cout << "[INFO] Inserting regular user\n";

   //INSERT INTO user (username, auth_token, asym_priv_key, asym_priv_key_len)
    if (sqlite3_bind_text(stmtInsertRegUser, 1, user_data.new_username, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertRegUser, 2, user_data.new_token_hash, HASH_SIZE, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertRegUser, 3, user_data.new_priv_key.priv_key, user_data.new_priv_key.priv_key_len, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int(stmtInsertRegUser, 4, user_data.new_priv_key.priv_key_len) != SQLITE_OK
        )
    std::cerr << "[ERROR] Failed to bind full regular user data\n";

    if (sqlite3_step(stmtInsertRegUser) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to insert reg user\n";
    }
}

void UserDAO::insertNewSecureUser(new_user_struct_sec user_data) {
    sqlite3_reset(stmtInsertSecUser);
    sqlite3_clear_bindings(stmtInsertSecUser);

    // "INSERT INTO user_sec (username, auth_token hash_size, auth_token_raw_enc 64, asym_priv_key, asym_priv_key_len, seed_phrase_hash)

    std::cout << "[INFO] Inserting secure user\n";

    if (sqlite3_bind_text(stmtInsertSecUser, 1, user_data.new_username, -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertSecUser, 2, user_data.new_token_hash, HASH_SIZE, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertSecUser, 3, user_data.new_token_encrypted, 64, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertSecUser, 4, user_data.new_priv_key.priv_key, user_data.new_priv_key.priv_key_len, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int(stmtInsertSecUser, 5, user_data.new_priv_key.priv_key_len) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertSecUser, 6, user_data.seed_phrase, 32, SQLITE_TRANSIENT) != SQLITE_OK
        )
        std::cerr << "[ERROR] Failed to bind full secure user data\n";

    if (sqlite3_step(stmtInsertSecUser) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to insert sec user\n";
    }
}

void UserDAO::insertUserPrivateKey(std::string username, priv_key_w_length priv_key) {
    sqlite3_reset(stmtInsertPrivKey);
    sqlite3_clear_bindings(stmtInsertPrivKey);


    std::cout << "[INFO] Inserting user private key\n";

    //UPDATE user SET asym_priv_key = ?, asym_priv_key_len = ? WHERE username = ?"

    if (sqlite3_bind_text(stmtInsertPrivKey, 1, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_blob(stmtInsertPrivKey, 2, priv_key.priv_key, priv_key.priv_key_len, SQLITE_TRANSIENT) != SQLITE_OK
        || sqlite3_bind_int(stmtInsertPrivKey, 3, priv_key.priv_key_len) != SQLITE_OK
        )
        std::cerr << "[ERROR] Failed to bind insert private key data\n";


    if (sqlite3_step(stmtInsertPrivKey) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to insert user private key\n";
    }

}


