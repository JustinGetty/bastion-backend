//
// Created by root on 5/19/25.
//

#ifndef USERDAO_H
#define USERDAO_H

#include <bastion_data.h>

#include "sqlite3.h"
#include "IUserReader.h"
#include "IUserWriter.h"

class UserDAO : public IUserReader, public IUserWriter {
   sqlite3 *db;
   sqlite3_stmt *stmtFindByUsername;
   sqlite3_stmt *stmtCheckUserSiteExists;
public:
   explicit UserDAO(sqlite3* db);
   ~UserDAO() override;
   //full_user_data findById(int id) override;
   full_user_data findByUsername(const std::string& uname) override;
   full_user_data findById(int id) override;

   void insertNewUser(const full_user_data& u) override;
   void updateAuthToken(int userId, const token_hash& newHash) override;
   bool getUserSiteDataExists(const std::string username) override;
};



#endif //USERDAO_H
