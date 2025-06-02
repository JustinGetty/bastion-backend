#ifndef MY_VALIDATION_WORK_H
#define MY_VALIDATION_WORK_H

#include <iostream>
#include <string>
#include <cstring>
#include "circular_queue.h"
#include "thread_pool.h"
#include "validation_work.h"
#include <bastion_data.h>
#include "../Headers/conn_data_storage.h"
#include "databaseq.h"
#include "../Headers/cryptography.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <algorithm>
#include "database_comm_v2.h"
#include <openssl/sha.h>



//TODO need a way to validate more secure version where it decrypts the token hash that was encrypted when put in db
//TODO get all this shit out of a header file ahhh

extern CircularQueue<validation_work*> g_workQueue;
extern ConnectionDataStorage cds;

constexpr size_t MAX_TOKEN_LEN = 500;

inline bool decodeTokenToFixedBuffer(
    const std::string &b64,
    unsigned char outBuf[MAX_TOKEN_LEN],
    size_t &outLen) {
    //set up a BIO chain: base64 filter → memory buffer
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64.data(), (int)b64.size());
    if (!b64_bio || !mem_bio) {
        BIO_free_all(b64_bio);
        BIO_free_all(mem_bio);
        return false;
    }
    BIO *bio = BIO_push(b64_bio, mem_bio);
    //disable line breaks, idt mobile sends this anymore with line breaks regardless but redundancy ig
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);

    //read decoded bytes directly into outBuf
    int decoded = BIO_read(bio, outBuf, (int)MAX_TOKEN_LEN);
    BIO_free_all(bio);

    if (decoded <= 0) {
        return false;
    }
    //if the decoded data exceeds buffer length
    if ((size_t)decoded > MAX_TOKEN_LEN) {
        return false;
    }

    outLen = (size_t)decoded;
    return true;
}


inline std::string base64url(const unsigned char* data, size_t len) {
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bmem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data, len);
    BIO_flush(b64);

    BUF_MEM *bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string b64str(bptr->data, bptr->length);
    BIO_free_all(b64);

    for (auto &c : b64str) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    b64str.erase(std::find(b64str.begin(), b64str.end(), '='), b64str.end());
    return b64str;
}

inline std::string sha256_challenge(const std::string &verifier) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, verifier.data(), verifier.size());
    EVP_DigestFinal_ex(mdctx, hash, &hash_len);
    EVP_MD_CTX_free(mdctx);

    return base64url(hash, hash_len);
}


inline STATUS validate_challenge_code(ConnectionData *connData) {
    /*send request for code, while waiting to get it sleep
        hash the og code
        check if they match
        proceed/reject
     */
    std::string wait_msg = R"({"action": "og_challenge_code_req"})";
    connData->ws->send(wait_msg, uWS::OpCode::TEXT);
    connData->user_data.being_processed = true;

    //TODO change this to only wait for X time before aborting
    while (connData->user_data.being_processed == true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

     if (sha256_challenge(connData->original_challenge_code) != connData->base_64_sha_256_enc_challenge_hash) {
        std::cout << "[INFO] Challenge codes do not match.\n";
        return LOGIC_FAILURE;
    }
    return SUCCESS;
}
inline std::string strip_domain(std::string email) {
    int domain_index = email.find('@');
    return email.substr(0, domain_index);
}

inline STATUS create_email_hash_and_encode_it(std::string email_with_domain, std::string* hash_out) {
    std::string email_no_domain = strip_domain(email_with_domain);
    std::string local = strip_domain(email_with_domain);

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (!SHA256(reinterpret_cast<const unsigned char*>(local.data()),
                local.size(),
                digest))
    {
        return CRYPTO_FAILURE;
    }

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss << std::setw(2) << static_cast<int>(digest[i]);
    }
    *hash_out = oss.str();

    return SUCCESS;
}



class MyValidationWork : public validation_work {
public:
    MyValidationWork(
        bool is_secure_mode,
        int id,
        int user_id,
        int connection_id,
        //make references
        const std::string token_hash_encoded,
        const std::string sym_key_iv_encoded,
        bool is_approved,
        bool is_signup,
        const std::string user_email)
        :
          is_secure_mode_(is_secure_mode),
          id_(id),
          user_id_(user_id),
          connection_id_(connection_id),
          token_hash_encoded(token_hash_encoded),
          sym_key_iv_encoded(sym_key_iv_encoded),
          is_approved_(is_approved),
          is_signup_(is_signup),
          email_(user_email)
    {
    }

    void execute() override {
        if (is_secure_mode_ == false) {
            //TODO validate approval BOOL and add to request
            std::cout << "[INFO] Executing regular validation work for: " << id_ << std::endl;

            unsigned char sym_key_iv_buffer[256];
            size_t sym_key_iv_length = 0;

            bool decode_sym_status = decodeTokenToFixedBuffer(sym_key_iv_encoded, sym_key_iv_buffer, sym_key_iv_length);
            printf("Decoded sym_iv_buffer\n");
            for (auto& i : sym_key_iv_buffer) {
                printf("%02x", i);
            }
            printf("\n");

            unsigned char encrypted_token_hash_buffer[256];
            size_t encrypted_token_hash_length = 0;

            bool decode_tok_status = decodeTokenToFixedBuffer(token_hash_encoded, encrypted_token_hash_buffer, encrypted_token_hash_length);
            printf("Decoded token sym encrypted\n");
            for (auto& i : encrypted_token_hash_buffer) {
                printf("%02x", i);
            }
            printf("\n");




            ConnectionData *data_from_storage = cds.get_connection_data(connection_id_);
            if (data_from_storage->user_data.fail_this == true) {
                data_from_storage->user_data.being_processed = false;
                data_from_storage->user_data.fail_this = false;
                std::cout << "[INFO] Aborting signin.\n";
                return;
            }
            std::cout << "[INFO] Data pulled from storage with id: " << data_from_storage->connection_id << "\n";

            unsigned char decrypted_sym_iv[KEY_SIZE + IV_SIZE] = {0};
            int decrypted_sym_iv_len = 0;
            if (decrypt_with_private_key(data_from_storage->user_data.priv_key_w_len.priv_key, data_from_storage->user_data.priv_key_w_len.priv_key_len,
                                        sym_key_iv_buffer, sym_key_iv_length, //can also use sym_key_iv_length
                                        decrypted_sym_iv, &decrypted_sym_iv_len) != SUCCESS)

            {
                std::fprintf(stderr, "[ERROR] Asymmetric decryption of key/IV failed\n");
            }

            if (decrypted_sym_iv_len != (KEY_SIZE + IV_SIZE)) {
                std::fprintf(stderr, "[ERROR] Decrypted key/IV length mismatch\n");
            }


            unsigned char recovered_key[KEY_SIZE] = {0};
            unsigned char recovered_iv[IV_SIZE] = {0};
            std::memcpy(recovered_key, decrypted_sym_iv, KEY_SIZE);
            std::memcpy(recovered_iv, decrypted_sym_iv + KEY_SIZE, IV_SIZE);

            unsigned char decrypted_sym_encrypted[256] = {0};
            int decrypted_sym_encrypted_len = 0;
            if (decrypt_with_private_key(data_from_storage->user_data.priv_key_w_len.priv_key, data_from_storage->user_data.priv_key_w_len.priv_key_len,
                                         encrypted_token_hash_buffer, encrypted_token_hash_length,
                                         decrypted_sym_encrypted, &decrypted_sym_encrypted_len) != SUCCESS)
            {
                std::fprintf(stderr, "[ERROR] Asymmetric decryption of wrapped token hash failed\n");
            }


            unsigned char final_decrypted_hash[TOKEN_SIZE] = {0};
            if (sym_decrypt(decrypted_sym_encrypted, &decrypted_sym_encrypted_len,
                            recovered_key, recovered_iv,
                            final_decrypted_hash) != SUCCESS)
            {
                std::fprintf(stderr, "[ERROR] Symmetric decryption of token failed\n");
            }

            token_hash computed_hash;

            compute_token_hash(final_decrypted_hash, TOKEN_SIZE, computed_hash);

            //TODO need to read in the actual success or reject as well
            if (constant_time_compare(data_from_storage->user_data.enc_auth_token, computed_hash, HASH_SIZE) == SUCCESS) {
                printf("[INFO] Token verification successful.\n");

                STATUS challenge_verification_status = validate_challenge_code(data_from_storage);
                if (challenge_verification_status != SUCCESS) {
                    std::cout << "[INFO] Challenge codes do not match.\n";
                    std::string failure_msg = R"({"status": "rejected"})";
                    std::string uname_str(data_from_storage->username);
                    STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, false);
                    data_from_storage->ws->send(failure_msg, uWS::OpCode::TEXT);
                    return;
                }

                std::string username_str(data_from_storage->username);
                STATUS update_user_site_usage_status = update_user_site_last_usage(&username_str, &data_from_storage->spa_id);

                //send this back to client
                uWS::WebSocket<false, true, ConnectionData> *ws = data_from_storage->ws;
                //TODO send back this -> data_from_storage->transaction_id!! and og_challenge_code_req
                std::string success_msg;
                if (is_approved_ == true) {
                    success_msg = R"({"status": "approved"})";
                    if (is_signup_) {

                        //hash email
                        //username, email, hash, id
                        std::string email_hash;;
                        STATUS email_hash_status = create_email_hash_and_encode_it(email_, &email_hash);
                        if (email_hash_status != SUCCESS) {
                            //TODO handle error
                        } else {
                            STATUS email_insert_status = insert_user_email_by_username(std::string(data_from_storage->username), email_, email_hash, data_from_storage->spa_id);
                        }
                    }
                } else if (is_approved_ == false) {
                    success_msg = R"({"status": "rejected"})";
                }
                std::string uname_str(data_from_storage->username);
                STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, is_approved_);
                ws->send(success_msg, uWS::OpCode::TEXT);
                return;

            } else {
                printf("[INFO] Token verification failed. SignIn rejected.\n");
                uWS::WebSocket<false, true, ConnectionData> *ws = data_from_storage->ws;
                std::string uname_str(data_from_storage->username);
                STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, false);
                std::string failure_msg = R"({"status": "rejected"})";
                ws->send(failure_msg, uWS::OpCode::TEXT);
            }
        }







        else if (is_secure_mode_ == true) {


            // in this mode the token is sent over only encoded and then encrypted with pub key

            std::cout << "[INFO] Executing regular validation work " << id_ << std::endl;

            std::cout << "[INFO] Received token: \n" << token_hash_encoded << std::endl;
            //unsigned char decoded_token_hash[256];
            //decode_fixed_length(token_hash_encoded, decoded_token_hash, 256);

             unsigned char buffer[MAX_TOKEN_LEN];
             size_t length = 0;

             bool stat = decodeTokenToFixedBuffer(token_hash_encoded, buffer, length);

             std::cout << "decoded " << length << " bytes:\n";
             for (size_t i = 0; i < length; ++i) {
                 printf("%02x", buffer[i]);
             }
             printf("\n");
             unsigned char decoded_token_hash[length];
             memcpy(decoded_token_hash, buffer, length);


            ConnectionData *data_from_storage = cds.get_connection_data(connection_id_);
            if (data_from_storage->user_data.fail_this == true) {
                data_from_storage->user_data.being_processed = false;
                data_from_storage->user_data.fail_this = false;
                std::cout << "[INFO] Aborting signin.\n";
                return;
            }
            std::cout << "[INFO] Data pulled from storage with id: "     << data_from_storage->connection_id << "\n";

            int decrypted_token_len;
            token decrypted_token;
            if (decrypt_with_private_key(data_from_storage->user_data.priv_key_w_len.priv_key, data_from_storage->user_data.priv_key_w_len.priv_key_len,
                                        decoded_token_hash, length,
                                        decrypted_token, &decrypted_token_len) != SUCCESS)

            {
                std::fprintf(stderr, "[ERROR] Asymmetric decryption of key/IV failed\n");
            }

            std::cout << "Token decrypted:\n";
            for (size_t i = 0; i < decrypted_token_len; ++i) {
                printf("%02x", decrypted_token[i]);
            }
            printf("\n");


            token_hash computed_hash{};

            compute_token_hash(decrypted_token, TOKEN_SIZE, computed_hash);

            std::cout << "token hash computed:\n";
            for (size_t i = 0; i < TOKEN_SIZE; ++i) {
                printf("%02x", computed_hash[i]);
            }
            printf("\n");

           token_hash token_from_storage{};
           memcpy(token_from_storage, data_from_storage->user_data.enc_auth_token, TOKEN_SIZE);
            std::cout << "token from storage:\n";
            for (size_t i = 0; i < TOKEN_SIZE; ++i) {
                printf("%02x", token_from_storage[i]);
            }
            printf("\n");
            //TODO need to read in the actual success or reject as well!! super importanttttttttt. prob just different endpoint lol
            if (constant_time_compare(data_from_storage->user_data.enc_auth_token, computed_hash, HASH_SIZE) == SUCCESS) {
                printf("[INFO] Token verification successful.\n");

                STATUS challenge_verification_status = validate_challenge_code(data_from_storage);
                if (challenge_verification_status != SUCCESS) {
                    std::cout << "[INFO] Challenge codes do not match.\n";
                    std::string failure_msg = R"({"status": "rejected"})";
                    std::string uname_str(data_from_storage->username);
                    STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, false);
                    data_from_storage->ws->send(failure_msg, uWS::OpCode::TEXT);
                    return;
                }


                std::string username_str(data_from_storage->username);
                STATUS update_user_site_usage_status = update_user_site_last_usage(&username_str, &data_from_storage->spa_id);


                //send this back to client
                uWS::WebSocket<false, true, ConnectionData> *ws = data_from_storage->ws;
                //TODO send back this -> data_from_storage->transaction_id!! and og_challenge_code_req
                std::string success_msg;
                if (is_approved_ == true) {
                    success_msg = R"({"status": "approved"})";
                    if (is_signup_) {

                        //hash email
                        //username, email, hash, id
                        std::string email_hash;;
                        STATUS email_hash_status = create_email_hash_and_encode_it(email_, &email_hash);
                        if (email_hash_status != SUCCESS) {
                            //TODO handle error
                        } else {
                            STATUS email_insert_status = insert_user_email_by_username(std::string(data_from_storage->username), email_, email_hash, data_from_storage->spa_id);
                        }
                    }
                } else if (is_approved_ == false) {
                    success_msg = R"({"status": "rejected"})";
                }
                std::string uname_str(data_from_storage->username);
                STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, is_approved_);
                ws->send(success_msg, uWS::OpCode::TEXT);
                return;

            } else {
                printf("[INFO] Token verification failed. SignIn rejected.\n");
                uWS::WebSocket<false, true, ConnectionData> *ws = data_from_storage->ws;
                std::string uname_str(data_from_storage->username);
                STATUS added_to_db = insert_site_request_v2(&data_from_storage->site_id, &uname_str, false);
                std::string failure_msg = R"({"status": "rejected"})";
                ws->send(failure_msg, uWS::OpCode::TEXT);
            }
        } else {
            //ERROR
        }



    }

private:
    int id_;
    int user_id_;
    const std::string token_hash_encoded;
    const std::string sym_key_iv_encoded;
    int connection_id_;
    bool is_secure_mode_;
    bool is_approved_;
    bool is_signup_;
    const std::string email_;
};
#endif // MY_VALIDATION_WORK_H
