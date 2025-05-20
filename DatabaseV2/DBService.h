//
// Created by root on 5/19/25.
//

#ifndef DBSERVICE_H
#define DBSERVICE_H
#include "Scheduler.h"
#include "UserDAO.h"
#include "Future.h"
#include "DatabaseRequest.h"
#include "DeviceDAO.h"
#include <bastion_data.h>
#include "IDeviceTokenStore.h"
#include "IEmailWriter.h"

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
