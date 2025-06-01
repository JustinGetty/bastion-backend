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
   sqlite3_stmt *stmtGetSiteData;
   sqlite3_stmt *stmtUpdateSiteUsage;
   sqlite3_stmt *stmtUpdateLastSiteUsage;

   sqlite3_stmt *stmtInsertRegUser;
   sqlite3_stmt *stmtInsertSecUser;
   sqlite3_stmt *stmtInsertPrivKey;

   sqlite3_stmt *stmtCheckUsernameExists;

   sqlite3_stmt *stmtGetSeedPhraseHash;
   sqlite3_stmt *stmtGetSymEncAuthToken;
   sqlite3_stmt *stmtGetDeviceToken;

public:
   explicit UserDAO(sqlite3* db);
   ~UserDAO() override;
   //full_user_data findById(int id) override;
   full_user_data findByUsername(const std::string& uname) override;
   full_user_data findById(int id) override;

   void insertNewUser(const full_user_data& u) override;
   void updateAuthToken(int userId, const token_hash& newHash) override;
   void updateSiteUsage(const std::string spa_id) override;
   void updateLastUserSiteUsage(const std::string username, const std::string spa_id) override;

   bool getUserSiteDataExists(const std::string username) override;
   bool getUsernameExists(const std::string username) override;

   std::vector<site_data_for_mobile> getSiteDataForMobileUser(std::string username) override;


   void insertNewRegularUser(new_user_struct user_data) override;
   void insertNewSecureUser(new_user_struct_sec user_data) override;
   void insertUserPrivateKey(std::string username, priv_key_w_length priv_key) override;


   std::array<unsigned char, 32> getSeedPhraseHash(const std::string username) override;
   std::array<unsigned char, 64> getSymEncAuthToken(const std::string username) override;
   std::string getDeviceToken(const std::string username) override;


};



#endif //USERDAO_H
