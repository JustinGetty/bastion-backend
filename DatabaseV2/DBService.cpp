//
// Created by root on 5/19/25.
//

#include "DBService.h"

DBService::DBService(
    Scheduler&                             sched_,
    std::unique_ptr<IUserReader>           userReader,
    std::unique_ptr<IUserWriter>           userWriter,
    std::unique_ptr<IDeviceTokenStore>     deviceStore,
    std::unique_ptr<IEmailWriter> emailWriter)
  : sched      (sched_)
  , rdr        (std::move(userReader))
  , wtr        (std::move(userWriter))
  , devStore   (std::move(deviceStore))
  , emailWtr   (std::move(emailWriter))
{}

// —————————————————————————————————————————————————
// Public API
// —————————————————————————————————————————————————
Future<full_user_data> DBService::getUserById(int id) {
    return asyncExec<full_user_data>(
        [this, id]() {
            return rdr->findById(id);
        }
    );
}

Future<full_user_data> DBService::getUserByName(const std::string& uname) {
    return asyncExec<full_user_data>(
        [this, uname]() {
            return rdr->findByUsername(uname);
        }
    );
}

Future<void> DBService::createUser(const full_user_data& u) {
    return asyncExec<void>(
        [this, u]() {
            return wtr->insertNewUser(u);
        }
    );
}

Future<void> DBService::changeAuthToken(int userId,
                                        const token_hash& newHash) {
    return asyncExec<void>(
        [this, userId, newHash]() {
            wtr->updateAuthToken(userId, newHash);
        }
    );
}

Future<ios_device_token> DBService::fetchDeviceToken(const std::string& uname) {
    return asyncExec<ios_device_token>(
        [this, uname]() {
            return devStore->getTokenForUser(uname);
        }
    );
}

Future<void> DBService::storeDeviceToken(const std::string& uname,
                                         const ios_device_token& tok) {
    return asyncExec<void>(
        [this, uname, tok]() {
            devStore->insertOrUpdateToken(uname, tok);
        }
    );
}

Future<void> DBService::storeUserEmail(const std::string& uname, const std::string& email, const std::string& emailHash, const std::string& client_spa_id) {
    return asyncExec<void>(
        [this, uname, email, emailHash, client_spa_id]() {
            emailWtr->insertNewUserEmail(&uname, &email, &emailHash, &client_spa_id);
        }
    );
}


Future<bool> DBService::checkUserSite(const std::string& uname) {
    return asyncExec<bool>(
        [this, uname]() {
            return rdr->getUserSiteDataExists(uname);
        }
    );
}

Future<std::vector<site_data_for_mobile>> DBService::getSiteDataForMobile(const std::string& uname) {
    return asyncExec<std::vector<site_data_for_mobile>>(
        [this, uname]() {
            //user reader get
            return rdr->getSiteDataForMobileUser(uname);
        }
    );
}



//template to handle void
template<typename T, typename Fn>
Future<T> DBService::asyncExec(Fn work) {
    // Wrap the work in a MethodRequest:
    auto req = std::make_unique<DatabaseRequest<T>>(std::function<T()>{std::move(work)});
    Future<T> fut = req->getFuture();
    sched.enqueue(std::move(req));
    return fut;
}

//explicit instantiations for the types we use:
template Future<full_user_data>       DBService::asyncExec<full_user_data>(std::function<full_user_data()>);
template Future<void>                 DBService::asyncExec<void>(std::function<void()>);
template Future<ios_device_token>     DBService::asyncExec<ios_device_token>(std::function<ios_device_token()>);
template Future<bool>                 DBService::asyncExec<bool>(std::function<bool()>);
template Future<std::vector<site_data_for_mobile>> DBService::asyncExec<std::vector<site_data_for_mobile>>(std::function<std::vector<site_data_for_mobile>()>);

