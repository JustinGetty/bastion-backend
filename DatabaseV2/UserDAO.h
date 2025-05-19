//
// Created by root on 5/19/25.
//

#ifndef USERDAO_H
#define USERDAO_H

#include "sqlite3.h"
#include "user.h"

class UserDAO : public DAO<User>{
   sqlite3 *db;
   sqlite3_stmt *stmtFindById;
public:
   explicit UserDAO(sqlite3* db);
   ~UserDAO() override;
   User findById(int id) override;
   void save(const User& u) override;
};



#endif //USERDAO_H
