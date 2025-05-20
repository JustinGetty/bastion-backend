//
// Created by root on 5/20/25.
//

#ifndef IUSERWRITER_H
#define IUSERWRITER_H
#include <bastion_data.h>

struct IUserWriter {
    virtual void insertNewUser(const full_user_data& u) = 0;
    virtual void updateAuthToken(int userId, const token_hash& newHash) = 0;
    virtual ~IUserWriter() = default;
};

#endif //IUSERWRITER_H
