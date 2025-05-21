//
// Created by root on 5/21/25.
//

#ifndef EMAILSYS_H
#define EMAILSYS_H
#include <bastion_data.h>
#include <string>


class EmailSys {
public:
    EmailSys(const std::string *username, const std::string* email);
    STATUS send_email_for_verification();
    bool get_verification_status();
    STATUS validate_verification_codes(std::string rec_verif_code);
    std::string get_verification_code();


private:
    std::string username;
    std::string user_email;
    bool is_verified;
    std::string verification_code;
    std::string generate_verification_code();
};



#endif //EMAILSYS_H
