#ifndef DATABASEQ_H
#define DATABASEQ_H
#include <bastion_data.h>

int insertByUserRowVals(int argc, char *username, char **argr, char **argv);

void send_post_query(const char *query);


size_t get_der_blob_total_length(const unsigned char *der_blob);

/* --------- PROD ------*/

STATUS get_basic_user_by_id(int userID, user_data_basic *user_data);
STATUS post_basic_user_data(user_data_basic user_data);
STATUS get_full_user_data(int user_id, full_user_data *user_data);
STATUS get_full_user_data_by_uname(bastion_username *uname, full_user_data *user_data);
STATUS post_full_user_data(full_user_data *user_data);
STATUS store_token_hash(const int user_id, const unsigned char *hash, const size_t hash_len);
STATUS get_token_hash(const int id, token_hash hash_out);
STATUS get_user_private_key(const int user_id, priv_key_w_length *priv_key_full);
STATUS store_user_private_key(const int user_id, priv_key_w_length *priv_key_full);
STATUS get_user_sym_key(const int user_id, sym_key_full *sym_key);
STATUS store_user_sym_key(const int user_id, const sym_key_full *sym_key);
void print_hex(unsigned char *data, int length);
STATUS check_username_exists(bastion_username *username, bool *output);
STATUS add_new_user_to_db(new_user_struct *user_data);
STATUS add_new_sec_user_to_db(new_user_struct_sec *user_data);
STATUS get_seed_phrase_hash(bastion_username* username, seed_phrase_hash *seed_phrase);
STATUS get_sym_enc_auth_token(bastion_username *username, token_sec *token_enc);
STATUS store_user_priv_key_by_username(bastion_username *username, priv_key_w_length priv_key);
STATUS get_client_id_from_spa_id(std::string *spa_id, int *client_id);
STATUS get_device_token_by_username(bastion_username* username, std::string *device_token_out);
#endif
