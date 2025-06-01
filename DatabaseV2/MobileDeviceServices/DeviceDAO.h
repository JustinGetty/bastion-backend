//
// Created by root on 5/20/25.
//

#ifndef DEVICEDAO_H
#define DEVICEDAO_H
#include <bastion_data.h>
#include "IDeviceTokenStore.h"
#include "sqlite3.h"


class DeviceDAO : public IDeviceTokenStore {
   sqlite3 *db;
   sqlite3_stmt *stmtInsertApnsByUsername;
public:
   explicit DeviceDAO(sqlite3* db_);
   ~DeviceDAO() override;

   void insertOrUpdateToken(const std::string& uname, const ios_device_token& token) override;

};



#endif //DEVICEDAO_H
