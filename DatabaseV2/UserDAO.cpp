//
// Created by root on 5/19/25.
//

#include "UserDAO.h"

UserDAO::UserDAO(sqlite3* _db): db(_db) {
    const char* SQL = "SELECT id, username FROM user WHERE id = ?";
    if (sqlite3_prepare_v2(db, SQL, -1, &stmtFindById, nullptr) != SQLITE_OK)
        throw std::runtime_error("Failed to prepare statement");
}

UserDAO::~UserDAO() {
    sqlite3_finalize(stmtFindById);
}

User UserDAO::findById(int id) {
    sqlite3_reset(stmtFindById);
    sqlite3_clear_bindings(stmtFindById);
    sqlite3_bind_int(stmtFindById, 1, id);

    User u{};
    if (sqlite3_step(stmtFindById) == SQLITE_ROW) {
        u.id       = sqlite3_column_int(stmtFindById, 0);
        u.username = reinterpret_cast<const char*>(sqlite3_column_text(stmtFindById,1));
    }
    return u;
}

void UserDAO::save(const User& u) {
    //INSERT QUEYRRHJSBFJHBS
}