//
// Created by root on 5/19/25.
//

#ifndef DBSERVICE_H
#define DBSERVICE_H
#include "GenericStuff/Scheduler.h"
#include "UserServices/UserDAO.h"
#include "GenericStuff/Future.h"
#include "GenericStuff/DatabaseRequest.h"
#include "MobileDeviceServices/DeviceDAO.h"
#include <bastion_data.h>
#include "MobileDeviceServices/IDeviceTokenStore.h"
#include "EmailServices/IEmailWriter.h"

class DBService {
public:
    DBService(Scheduler& sched,
              std::unique_ptr<IUserReader>  userReader,
              std::unique_ptr<IUserWriter>  userWriter,
              std::unique_ptr<IDeviceTokenStore> deviceStore,
              std::unique_ptr<IEmailWriter>  emailWriter
              );

    Future<full_user_data> getUserById(int id);
    Future<full_user_data> getUserByName(const std::string& uname);
    Future<void> createUser(const full_user_data& u);
    Future<void>           changeAuthToken(int userId,
                                            const token_hash& newHash);

    Future<ios_device_token> fetchDeviceToken(const std::string& uname);
    Future<void>             storeDeviceToken(const std::string& uname,
                                              const ios_device_token& tok);
    Future<void> storeUserEmail(const std::string& uname, const std::string& email, const std::string& emailHash, const std::string& client_spa_id);
    Future<bool> checkUserSite(const std::string& uname);
    Future <std::vector<site_data_for_mobile>> getSiteDataForMobile(const std::string& uname);
    Future<void> updateSiteUsageCount(const std::string &site_spa_id);
    Future<void> updateUserLastUsedTime(const std::string &username, const std::string &site_spa_id);
    Future<void> insertRegUser(new_user_struct &user_data);
    Future<void> insertSecUser(new_user_struct_sec &user_data);
    Future<void> insertPrivKey(std::string &username, priv_key_w_length &priv_key);



private:
    Scheduler&                         sched;
    std::unique_ptr<IUserReader>      rdr;
    std::unique_ptr<IUserWriter>      wtr;
    std::unique_ptr<IDeviceTokenStore> devStore;
    std::unique_ptr<IEmailWriter>      emailWtr;

    template<typename T, typename Fn>
    Future<T> asyncExec(Fn work);
};

#endif //DBSERVICE_H
