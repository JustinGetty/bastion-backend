//
// Created by root on 5/19/25.
//

#ifndef DATABASE_COMM_V2_H
#define DATABASE_COMM_V2_H
#include <bastion_data.h>
#include "sqlite3.h"
#include "../DatabaseV2/GenericStuff/Scheduler.h"
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
STATUS check_if_username_exists(std::string *username, bool* out);
STATUS get_site_data_for_mobile(const std::string *username, std::vector<site_data_for_mobile>* site_data_out);
STATUS update_site_usage_count(const std::string *spa_id);
STATUS update_user_site_last_usage(const std::string * username, const std::string *spa_id);
STATUS add_new_user_to_db_v2(new_user_struct *user_data);
STATUS add_new_sec_user_to_db_v2(new_user_struct_sec *user_data);
STATUS store_user_priv_key_by_username_v2(std::string *username, priv_key_w_length* priv_key);
STATUS get_seed_phrase_hash_v2(std::string *username, seed_phrase_hash* seed_phrase_out);
STATUS get_sym_enc_auth_token_v2(std::string *username, token_sec* auth_token_out);
STATUS get_device_token_v2(std::string *username, std::string *device_token_out);
STATUS insert_site_request_v2(int *site_id, std::string *username, bool approved);
STATUS get_site_id_by_spa_id_v2(std::string *spa_id, int* site_id);


#endif //DATABASE_COMM_V2_H
