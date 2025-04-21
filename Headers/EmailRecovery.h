//
// Created by root on 4/14/25.
//

#ifndef EMAILRECOVERY_H
#define EMAILRECOVERY_H
#include <bastion_data.h>
#include <unordered_map>
#include <iostream>

//TODO when the user sends get request with code for approval, after verification delete this object

class EmailRecovery {

private:
    std::pmr::unordered_map<std::string, int> user_recovery_codes;

public:
    EmailRecovery();
    ~EmailRecovery();
    void add_user_recovery_code(std::string username, int recovey_code);
    void remove_user_recovery_code(std::string username);
    int get_user_recovery_code(std::string username);
    STATUS validate_code(std::string username, int given_code);
};



#endif //EMAILRECOVERY_H
