//
// Created by root on 5/20/25.
//

#ifndef EMAILDAO_H
#define EMAILDAO_H
#include "IEmailWriter.h"
#include "sqlite3.h"


class EmailDAO : public IEmailWriter{
    sqlite3 *db;
    sqlite3_stmt *stmtInsertUserEmail;
public:
    explicit EmailDAO(sqlite3* db);
    void insertNewUserEmail(const std::string* username,
        const std::string* email_raw,
        const std::string* email_hash,
        const std::string* client_spa_id) override;
    ~EmailDAO() override;
};



#endif //EMAILDAO_H
