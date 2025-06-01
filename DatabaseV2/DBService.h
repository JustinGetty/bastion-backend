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
#include "SiteServices/ISiteReader.h"
#include "SiteServices/ISiteWriter.h"

class DBService {
public:
    DBService(Scheduler& sched,
              std::unique_ptr<IUserReader>  userReader,
              std::unique_ptr<IUserWriter>  userWriter,
              std::unique_ptr<IDeviceTokenStore> deviceStore,
              std::unique_ptr<IEmailWriter>  emailWriter,
              std::unique_ptr<ISiteReader> siteReader,
              std::unique_ptr<ISiteWriter> siteWriter
              );

    Future<full_user_data> getUserById(int id);
    Future<full_user_data> getUserByName(const std::string& uname);
    Future<void> createUser(const full_user_data& u);
    Future<void>           changeAuthToken(int userId,
                                            const token_hash& newHash);

    Future<void>             storeDeviceToken(const std::string& uname,
                                              const ios_device_token& tok);
    Future<void> storeUserEmail(const std::string& uname, const std::string& email, const std::string& emailHash, const std::string& client_spa_id);
    Future<bool> checkUserSite(const std::string& uname);
    Future<bool> checkIfUsernameExists(std::string &uname);
    Future <std::vector<site_data_for_mobile>> getSiteDataForMobile(const std::string& uname);
    Future<void> updateSiteUsageCount(const std::string &site_spa_id);
    Future<void> updateUserLastUsedTime(const std::string &username, const std::string &site_spa_id);
    Future<void> insertRegUser(new_user_struct &user_data);
    Future<void> insertSecUser(new_user_struct_sec &user_data);
    Future<void> insertPrivKey(std::string &username, priv_key_w_length &priv_key);


    Future<std::array<unsigned char, 32>> getSeedPhraseHashForUser(const std::string &uname);
    Future<std::array<unsigned char, 64>> getSymEncAuthTokenForUser(const std::string &uname);
    Future<std::string> getDeviceTokenForUser(const std::string &uname);

    Future<int> getSiteIDBySPA(const std::string &spa_id);
    Future<void> insertReqInDB(const int& site_id, const std::string& username, const int& approved);

private:
    Scheduler&                         sched;
    std::unique_ptr<IUserReader>      rdr;
    std::unique_ptr<IUserWriter>      wtr;
    std::unique_ptr<IDeviceTokenStore> devStore;
    std::unique_ptr<IEmailWriter>      emailWtr;
    std::unique_ptr<ISiteReader>       siteRdr;
    std::unique_ptr<ISiteWriter>       siteWtr;

    template<typename T, typename Fn>
    Future<T> asyncExec(Fn work);
};

#endif //DBSERVICE_H
