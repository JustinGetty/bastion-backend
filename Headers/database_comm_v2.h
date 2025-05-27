//
// Created by root on 5/19/25.
//

#ifndef DATABASE_COMM_V2_H
#define DATABASE_COMM_V2_H
#include <bastion_data.h>
#include "sqlite3.h"
#include "../DatabaseV2/Scheduler.h"
#include "../DatabaseV2/DBService.h"

extern sqlite3*    g_db;
extern Scheduler   g_sched;
extern DBService*  g_dbService;

STATUS start_db_comm();
void shutdown_db_comm();
STATUS get_user_by_username_v2(bastion_username *uname, full_user_data *user_data);
STATUS insert_ios_device_token_by_username_v2(bastion_username *uname, ios_device_token *device_token);
STATUS insert_user_email_by_username(std::string uname, std::string email, std::string email_hash, std::string client_spa_id);
STATUS check_if_user_is_new_to_site(const std::string username, bool* out);
STATUS get_site_data_for_mobile(const std::string *username, std::vector<site_data_for_mobile>* site_data_out);
STATUS update_site_usage_count(const std::string *spa_id);
STATUS update_user_site_last_usage(const std::string * username, const std::string *spa_id);

#endif //DATABASE_COMM_V2_H
