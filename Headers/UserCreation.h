//
// Created by root on 4/7/25.
//

#ifndef USERCREATION_H
#define USERCREATION_H
#include <iostream>
#include <bastion_data.h>

STATUS create_new_user_unsec(std::string* username, new_user_outbound_data* user_data);
STATUS create_new_user_sec(bastion_username username, new_user_outbound_data* user_data);
STATUS process_new_user_to_send(new_user_outbound_data* user_data, std::string* user_data_json);



#endif //USERCREATION_H
