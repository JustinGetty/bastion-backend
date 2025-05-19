//
// Created by root on 5/19/25.
//

#ifndef USERDAO_H
#define USERDAO_H

#include <bastion_data.h>

#include "sqlite3.h"
#include "User.h"
#include "DAO.h"

class UserDAO : public DAO<full_user_data> {
   sqlite3 *db;
   sqlite3_stmt *stmtFindByUsername;
public:
   explicit UserDAO(sqlite3* db);
   ~UserDAO() override;
   full_user_data get_user_by_uname(std::string username) override;
};



#endif //USERDAO_H
