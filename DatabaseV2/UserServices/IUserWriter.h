//
// Created by root on 5/20/25.
//

#ifndef IUSERWRITER_H
#define IUSERWRITER_H
#include <bastion_data.h>

struct IUserWriter {
    virtual void insertNewUser(const full_user_data& u) = 0;
    virtual void updateAuthToken(int userId, const token_hash& newHash) = 0;
    virtual void updateSiteUsage(const std::string spa_id) = 0;
    virtual void updateLastUserSiteUsage(const std::string username, const std::string spa_id) = 0;

    virtual void insertNewRegularUser(new_user_struct user_data) = 0;
    virtual void insertNewSecureUser(new_user_struct_sec user_data) = 0;
    virtual void insertUserPrivateKey(std::string username, priv_key_w_length priv_key) = 0;


    virtual ~IUserWriter() = default;
};

#endif //IUSERWRITER_H
