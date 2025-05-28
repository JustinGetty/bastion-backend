#ifndef DATABASEQ_H
#define DATABASEQ_H
#include <bastion_data.h>

//---- unused ---- destroy --------------------------------

//int insertByUserRowVals(int argc, char *username, char **argr, char **argv);
//void send_post_query(const char *query);
//STATUS get_basic_user_by_id(int userID, user_data_basic *user_data);
//STATUS post_basic_user_data(user_data_basic user_data);
//STATUS get_full_user_data(int user_id, full_user_data *user_data);
//STATUS get_full_user_data_by_uname(bastion_username *uname, full_user_data *user_data);
//STATUS post_full_user_data(full_user_data *user_data);
//STATUS get_user_sym_key(const int user_id, sym_key_full *sym_key);
//STATUS store_user_sym_key(const int user_id, const sym_key_full *sym_key);
//STATUS update_device_token_ios_by_username(bastion_username *username, apns_token *device_token);
//STATUS check_if_user_is_in_site(bastion_username* username, bool *output);
//STATUS store_token_hash(const int user_id, const unsigned char *hash, const size_t hash_len);
//STATUS store_user_private_key(const int user_id, priv_key_w_length *priv_key_full);

//phase out
size_t get_der_blob_total_length(const unsigned char *der_blob);
void print_hex(unsigned char *data, int length);



/* --------- PROD ------*/
//PHASE OUT


//this goes into UserDAO
//subgrouped by return type

//void
STATUS add_new_user_to_db(new_user_struct *user_data);
STATUS add_new_sec_user_to_db(new_user_struct_sec *user_data);
//STATUS store_user_priv_key_by_username(bastion_username *username, priv_key_w_length priv_key);

//bool
STATUS check_username_exists(bastion_username *username, bool *output);

//Unique returnsss
STATUS get_token_hash(const int id, token_hash hash_out);
STATUS get_user_private_key(const int user_id, priv_key_w_length *priv_key_full);
STATUS get_seed_phrase_hash(bastion_username* username, seed_phrase_hash *seed_phrase);
STATUS get_sym_enc_auth_token(bastion_username *username, token_sec *token_enc);
STATUS get_device_token_by_username(bastion_username* username, apns_token *device_token_out);

//this goes into SiteDAO
STATUS get_client_id_from_spa_id(std::string *spa_id, int *client_id);
STATUS insert_request(const int site_id, bastion_username* username, const int approved);

#endif
