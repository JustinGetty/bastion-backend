//
// Created by root on 4/4/25.
//

#ifndef VALIDATE_USERNAME_H
#define VALIDATE_USERNAME_H
#include <bastion_data.h>
constexpr size_t MIN_USERNAME_LENGTH = 3;

std::string trim(const std::string &str);

bool isReservedUsername(const std::string &username);

bool isValidUsername(const std::string &inputUsername);

bool setUsername(const std::string &input, bastion_username &output);


#endif //VALIDATE_USERNAME_H
