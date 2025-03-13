#ifndef DATABASEQ_H
#define DATABASEQ_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <bastion_data.h>



/*
TODO:
1. implement https://sqlite.org/com/see.html
*/

int insertByUserRowVals(int argc, char *username, char **argr, char **argv);

void send_post_query(const char *query);



/* --------- PROD ------*/

STATUS get_basic_user_by_id(int userID, user_data_basic &user_data);
full_user_data_enc get_full_enc_user_by_id(int userID);
STATUS post_basic_user_data(user_data_basic user_data);
STATUS post_full_user_data(full_user_data_enc user_data);


#endif
