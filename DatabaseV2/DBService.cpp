//
// Created by root on 5/19/25.
//

#include "DBService.h"

DBService::DBService(
    Scheduler&                             sched_,
    std::unique_ptr<IUserReader>           userReader,
    std::unique_ptr<IUserWriter>           userWriter,
    std::unique_ptr<IDeviceTokenStore>     deviceStore,
    std::unique_ptr<IEmailWriter>          emailWriter,
    std::unique_ptr<ISiteReader>           siteReader,
    std::unique_ptr<ISiteWriter>           siteWriter
    )
  : sched      (sched_)
  , rdr        (std::move(userReader))
  , wtr        (std::move(userWriter))
  , devStore   (std::move(deviceStore))
  , emailWtr   (std::move(emailWriter))
  , siteRdr    (std::move(siteReader))
  , siteWtr    (std::move(siteWriter))
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



Future<void> DBService::updateSiteUsageCount(const std::string& site_spa_id) {
    return asyncExec<void>(
        [this, site_spa_id]() {
            wtr->updateSiteUsage(site_spa_id);
        }
    );
}

Future<void> DBService::updateUserLastUsedTime(const std::string &username, const std::string &site_spa_id) {
    return asyncExec<void>(
        [this, username, site_spa_id]() {
            wtr->updateLastUserSiteUsage(username, site_spa_id);
        }
        );
}

Future<void> DBService::insertRegUser(new_user_struct &user_data) {
    return asyncExec<void>(
        [this, user_data]() {
            wtr->insertNewRegularUser(user_data);
        }
    );
}


Future<void> DBService::insertSecUser(new_user_struct_sec &user_data) {
    return asyncExec<void>(
        [this, user_data]() {
            wtr->insertNewSecureUser(user_data);
        }
    );
}

Future<void> DBService::insertPrivKey(std::string &username, priv_key_w_length &priv_key) {
    return asyncExec<void>(
        [this, username, priv_key]() {
            wtr->insertUserPrivateKey(username, priv_key);
        }
        );
}

Future<bool> DBService::checkIfUsernameExists(std::string &uname) {
    return asyncExec<bool>(
        [this, uname]() {
            return rdr->getUsernameExists(uname);
        }
    );
}

Future<std::array<unsigned char, 32>> DBService::getSeedPhraseHashForUser(const std::string& uname) {
    return asyncExec<std::array<unsigned char, 32>>(
        [this, uname]() {
            return rdr->getSeedPhraseHash(uname);
        }
        );
}


Future<std::array<unsigned char, 64>> DBService::getSymEncAuthTokenForUser(const std::string& uname) {
    return asyncExec<std::array<unsigned char, 64>>(
        [this, uname]() {
            return rdr->getSymEncAuthToken(uname);
        }
        );
}


Future<std::string> DBService::getDeviceTokenForUser(const std::string& uname) {
    return asyncExec<std::string>(
        [this, uname]() {
            return rdr->getDeviceToken(uname);
        }
        );
}

Future<int> DBService::getSiteIDBySPA(const std::string &spa_id) {
    return asyncExec<int>(
        [this, spa_id]() {
            return siteRdr->getClientIdBySpaId(spa_id);
        }
        );
}

Future<void> DBService::insertReqInDB(const int& site_id, const std::string& username, const int& approved) {
   return asyncExec<void>(
       [this, site_id, username, approved]() {
           return siteWtr->insertRequest(site_id, username, approved);
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
template Future<int> DBService::asyncExec<int>(std::function<int()>);
template Future<std::array<unsigned char, 32>>                 DBService::asyncExec<std::array<unsigned char, 32>>(std::function<std::array<unsigned char, 32>()>);
template Future<std::array<unsigned char, 64>>                 DBService::asyncExec<std::array<unsigned char, 64>>(std::function<std::array<unsigned char, 64>()>);
template Future<std::array<unsigned char, 65>>                 DBService::asyncExec<std::array<unsigned char, 65>>(std::function<std::array<unsigned char, 65>()>);




