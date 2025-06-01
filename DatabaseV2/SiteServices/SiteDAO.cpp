//
// Created by root on 6/1/25.
//

#include "SiteDAO.h"
#include <bastion_data.h>

SiteDAO::SiteDAO(sqlite3* _db): db(_db) {
    //const char* SQL = "SELECT id, username FROM user WHERE id = ?";
    /*
    if (sqlite3_prepare_v2(db, SQL, -1, &stmtFindById, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
        */

    if (sqlite3_prepare_v2(db, INSERT_REQUEST_IN_DB, -1, &stmtInsertRequest, nullptr) != SQLITE_OK
        || sqlite3_prepare_v2(db, GET_CLIENT_ID_BY_SPA_ID, -1, &stmtGetSiteIdBySpaId, nullptr) != SQLITE_OK
        )

        //did you remember to finalize it?
        throw std::runtime_error("Failed to prepare statement");
}

SiteDAO::~SiteDAO() {
    sqlite3_finalize(stmtInsertRequest);
    sqlite3_finalize(stmtGetSiteIdBySpaId);
}


void SiteDAO::insertRequest(const int site_id, const std::string username, const int approved) {
    sqlite3_reset(stmtInsertRequest);
    sqlite3_clear_bindings(stmtInsertRequest);

    if (sqlite3_bind_int(stmtInsertRequest, 1, site_id) != SQLITE_OK
            || sqlite3_bind_text(stmtInsertRequest, 2, username.c_str(), -1, SQLITE_TRANSIENT) != SQLITE_OK
            || sqlite3_bind_int(stmtInsertRequest, 3, approved) != SQLITE_OK
            )
        std::cerr << "[ERROR] Failed to bind request\n";

    if (sqlite3_step(stmtInsertRequest) != SQLITE_DONE) {
        std::cerr << "[ERROR] Failed to insert request\n";
    } else {
        std::cout << "[INFO] Inserted request in DB\n";
    }
}

int SiteDAO::getClientIdBySpaId(const std::string spa_id) {
    sqlite3_reset(stmtGetSiteIdBySpaId);
    sqlite3_clear_bindings(stmtGetSiteIdBySpaId);

    if (sqlite3_)
}
