//
// Created by root on 5/20/25.
//

#ifndef IEMAILWRITER_H
#define IEMAILWRITER_H
#include <iostream>

struct IEmailWriter {
    virtual void insertNewUserEmail(const std::string* username,
        const std::string* email_raw,
        const std::string* email_hash,
        const std::string* client_spa_id) = 0;
    virtual ~IEmailWriter() = default;
};

#endif //IEMAILWRITER_H
