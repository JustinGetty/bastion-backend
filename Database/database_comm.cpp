#include "../Headers/databaseq.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <errno.h>
#include "../Headers/database_head.h"

//TODO get requests should not use such large data type, SPECIALIZE!!!


void print_hex(unsigned char *data, int length) {
    for (int i = 0; i < length; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int connect_to_database_daemon() {
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Socket no good");
        return sock;
    }
    printf("Socket: %d\n", sock);
    struct sockaddr_un server_addr;
    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, SQLITE_DAEMON_SOCKET_PATH);
    if (connect(sock, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        printf("Connection to database failed\n");
        return sock;
    }
    return sock;
}

query_data set_query_data(char type, query_real_type real_type, int num_params, query_param params[MAX_PARAMS]) {
    query_data data;
    memset(&data, 0, sizeof(data));
    data.type = type;
    data.real_type = real_type;
    data.num_params = num_params;
    for (int i = 0; i < num_params; i++) {
        data.params[i] = params[i];
    }
    return data;
}

query_param create_param_int(int value) {
    query_param param;
    param.type = PARAM_INT;
    param.data.int_val = value;
    return param;
}

query_param create_param_float(float value) {
    query_param param;
    param.type = PARAM_FLOAT;
    param.data.float_val = value;
    return param;
}

query_param create_param_text(char value[128]) {
    query_param param;
    param.type = PARAM_TEXT;
    strncpy(param.data.text_val, value, sizeof(param.data.text_val));
    return param;
}

query_param create_param_hash_token(const token_hash value) {
    query_param param;
    param.type = PARAM_TOKEN_HASH;
    memcpy(param.data.token_val_hash, value, sizeof(param.data.token_val_hash));
    return param;
}

query_param create_param_asym_key(priv_key_w_length priv_key) {
    query_param param;
    param.type = PARAM_ASM_KEY;
    memcpy(&param.data.priv_key_w_len, &priv_key, sizeof(param.data.priv_key_w_len));
    return param;
}
query_param create_param_sym_key(sym_key sym_key) {
    query_param param;
    param.type = PARAM_SYM_KEY;
    memcpy(&param.data.sym_key_val, sym_key, KEY_SIZE);
    return param;
}

query_param create_param_sym_iv(sym_iv iv) {
    query_param param;
    param.type = PARAM_SYM_IV;
    memcpy(&param.data.sym_iv_val, iv, IV_SIZE);
    return param;
}

query_param create_param_username(bastion_username *username) {
    query_param param;
    param.type = PARAM_USERNAME;
    char uname_temp[MAX_USERNAME_LENGTH];
    std::strcpy(param.data.username_val, *username);
    return param;
}

query_param create_param_token_enc(token_sec *token_enc_sec) {
    query_param param;
    param.type = PARAM_TOKEN_ENC;
    memcpy(&param.data.encrypted_raw_token, *token_enc_sec, sizeof(*token_enc_sec));
    return param;
}
query_param create_param_seed_phrase_hash(seed_phrase_hash seed_phrase_hash_) {
    query_param param;
    param.type = PARAM_SEED_PHRASE_HASH;
    memcpy(&param.data.seed_phrase_hash_, seed_phrase_hash_, 32);
    std::cout << "DEBUGGINGGGG AGG" << std::endl;
    print_hex(param.data.seed_phrase_hash_, 32);
    return param;
}
query_param create_param_apns_token(apns_token *apns_token) {
    query_param param;
    param.type = PARAM_APNS_DEVICE_TOKEN;
    memcpy(&param.data.apns_token_val, apns_token, APNS_TOKEN_SIZE);
    return param;
}


STATUS send_query(int sock, query_data data) {
    size_t total_sent = 0;
    size_t to_send = sizeof(query_data);
    const unsigned char *buffer = (const unsigned char *)&data;

    while (total_sent < to_send) {
        ssize_t sent = send(sock, buffer + total_sent, to_send - total_sent, 0);
        if (sent < 0) {
            return TOO_FEW_BYTES_SENT;
        }
        if (sent == 0) {
            return TOO_FEW_BYTES_SENT;
        }
        total_sent += sent;
    }

    return SUCCESS;
}

STATUS read_status(int sock) {
    STATUS status;
    size_t total_received = 0;
    size_t to_receive = sizeof(STATUS);
    unsigned char *buffer = (unsigned char *)&status;

    while (total_received < to_receive) {
        ssize_t received = recv(sock, buffer + total_received, to_receive - total_received, 0);
        if (received < 0) {
            return TOO_FEW_BYTES_RECEIVED;
        }
        if (received == 0) {
            return TOO_FEW_BYTES_RECEIVED;
        }
        total_received += received;
    }

    return status;
}


int receive_from_db(size_t to_receive, unsigned char *buffer, int sock) {
    size_t total_received = 0;
    while (total_received < to_receive) {
        ssize_t received = recv(sock, buffer + total_received, to_receive - total_received, 0);
        if (received < 0) {
            fprintf(stderr, "ERROR RECEIVING: %s\n", strerror(errno));
            return TOO_FEW_BYTES_RECEIVED;
        }
        if (received == 0) {
            break; // connection closed by peer
        }
        total_received += received;
    }
    return total_received;
}



size_t get_der_blob_total_length(const unsigned char *der_blob) {
    if (der_blob == NULL || ASYM_SIZE < 2) {
        return 0;
    }

    unsigned char length_byte = der_blob[1];
    size_t header_size = 0;
    size_t content_length = 0;

    if ((length_byte & 0x80) == 0) {
        content_length = length_byte;
        header_size = 2;
    } else {
        int num_length_bytes = length_byte & 0x7F;
        if (ASYM_SIZE < 2 + num_length_bytes) {
            return 0;
        }
        header_size = 2 + num_length_bytes;
        content_length = 0;
        for (int i = 0; i < num_length_bytes; i++) {
            content_length = (content_length << 8) | der_blob[2 + i];
        }
    }

    return header_size + content_length;
}


//-----------------------------------------------------------------------------------------
/*
STATUS get_basic_user_by_id(int userID, user_data_basic *user_data)
{
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_int(userID);

    query_data data = set_query_data('g', GET_BASIC_USER_BY_ID, 1, params);
    strncpy(data.query, GET_BASIC_USER_QUERY, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query Sent\n");


    size_t total_received = 0;
    size_t to_receive = sizeof(user_data_basic);
    unsigned char *buffer = (unsigned char *)user_data;

    while (total_received < to_receive) {
        ssize_t received = recv(sock, buffer + total_received, to_receive - total_received, 0);
        if (received < 0) {
            perror("recv error");
            return TOO_FEW_BYTES_RECEIVED;
        }
        if (received == 0) {
            // The connection has been closed before reading all the data.
            break;
        }
        total_received += received;
    }

    if (total_received != to_receive) {
            perror("recv error");
            return TOO_FEW_BYTES_RECEIVED;
    }

    printf("Username Retrieved: %s\n", user_data->username);

    if (user_data->status != 0) {
        close(sock);
        return DATABASE_FAILURE;
    }
    //error handling - if username is valid return success, add meta data in the response
    close(sock);
    return SUCCESS;
}


//for testing, not to be used in Prod
STATUS post_basic_user_data(user_data_basic user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_text(user_data.username);
    query_data data = set_query_data('p', POST_BASIC_USER, 2, params);

    strncpy(data.query, POST_BASIC_USER_QUERY, sizeof(data.query));
    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query Sent\n");

    STATUS post_status = read_status(sock);
    close(sock);
    return post_status;
}

//does not yet contain asym_key
STATUS post_full_user_data(full_user_data user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_text(user_data.username);
    params[1] = create_param_hash_token(user_data.enc_auth_token);
    params[2] = create_param_asym_key(user_data.priv_key_w_len);

    //fill data
    query_data data = set_query_data('p', POST_FULL_NEW_USER, 3, params);

    strncpy(data.query, POST_FULL_NEW_USER_QUERY, sizeof(data.query));
    printf("query: %s\n", POST_FULL_NEW_USER_QUERY);
    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query Sent\n");

    STATUS post_status = read_status(sock);
    close(sock);
    return post_status;
}
*/


STATUS store_token_hash(const int user_id, const token_hash token_hash_, const size_t hash_len) {
    query_param params[MAX_PARAMS];
    params[0] = create_param_hash_token(token_hash_);
    params[1] = create_param_int(user_id);
    query_data data = set_query_data('p', POST_AUTH_TOKEN, 2, params);
    strncpy(data.query, UPDATE_USER_AUTH_TOKEN_BY_ID, sizeof(data.query));

    //this can go into helper function
    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    add_to_queue(queryDataPtr);

    /* BLOCKING LOGIC, OPTIMIZE LATE TO ASYNC !!!*/
    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    STATUS process_status = queryDataPtr->status;
    std::cout << "Process status: " << process_status << "\n";
    if (process_status != SUCCESS) {
        return process_status;
    }
    std::cout << "Query processed\n";
    return process_status;
}
STATUS get_token_hash(const int id, token_hash hash_out) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_int(id);
    query_data data = set_query_data('g', GET_AUTH_TOKEN, 1, params);
    strncpy(data.query, GET_AUTH_TOKEN_BY_ID, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }

    printf("Query Sent\n");

    hash_token_struct token_hash;

    size_t total_received = 0;
    size_t to_receive = sizeof(hash_token_struct);
    unsigned char *buffer = (unsigned char *)&token_hash;
    while (total_received < to_receive) {
        ssize_t received = recv(sock, buffer + total_received, to_receive - total_received, 0);
        if (received < 0) {
            perror("recv error");
            return TOO_FEW_BYTES_RECEIVED;
        }
        if (received == 0) {
            break;
        }
        total_received += received;
    }

    if (total_received != to_receive) {
        return TOO_FEW_BYTES_RECEIVED;
    }

    if (token_hash.status_ == SUCCESS) {
        memcpy(hash_out, token_hash.token_hash_, HASH_SIZE);
    }

    return token_hash.status_;
}

STATUS get_user_private_key(const int user_id, priv_key_w_length *priv_key_full) {
    query_param params[MAX_PARAMS];
    params[0] = create_param_int(user_id);

    query_data data = set_query_data('g', GET_ASYM_PRIV_KEY, 1, params);
    strncpy(data.query, GET_USER_PRIVATE_KEY_BY_ID, sizeof(data.query));


    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    priv_key_w_length priv_key{};
    memcpy(priv_key.priv_key, queryDataPtr->processed_data.priv_key.priv_key, queryDataPtr->processed_data.priv_key.priv_key_len);
    priv_key.priv_key_len = queryDataPtr->processed_data.priv_key.priv_key_len;

    printf("Private key: \n");
    for (int i = 0; i < priv_key.priv_key_len; i++) {
        printf("%02x", priv_key.priv_key[i]);
    }
    printf("\n");

    STATUS status = queryDataPtr->status;
    std::cout << "priv key status: " << status << "\n";

    if (status != SUCCESS) {
        return DATABASE_FAILURE;
    }

    if (status == SUCCESS) {
        memcpy(priv_key_full, priv_key.priv_key, sizeof(priv_key.priv_key));
        priv_key_full->priv_key_len = priv_key.priv_key_len;
        size_t len = get_der_blob_total_length(priv_key.priv_key);
        if (len > 0) {
            priv_key_full->priv_key_len = len;
        } else {
            return DATABASE_FAILURE;
        }
    }
    return status;
}

STATUS store_user_private_key(const int user_id, priv_key_w_length *priv_key_full) {
    query_param params[MAX_PARAMS];
    params[0] = create_param_asym_key(*priv_key_full);
    params[1] = create_param_int(priv_key_full->priv_key_len);
    params[2] = create_param_int(user_id);

    query_data data = set_query_data('p', POST_ASYM_PRIV_KEY, 3, params);
    strncpy(data.query, UPDATE_USER_PRIV_KEY_BY_ID, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    add_to_queue(queryDataPtr);

    /* BLOCKING LOGIC, OPTIMIZE LATE TO ASYNC !!!*/
    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }
    STATUS process_status = queryDataPtr->status;
    std::cout << "Process status: " << process_status << "\n";
    if (process_status != SUCCESS) {
        return process_status;
    }
    std::cout << "Query processed\n";
    return process_status;
}
STATUS get_full_user_data(int user_id, full_user_data *user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_int(user_id);
    query_data data = set_query_data('g', GET_FULL_USER_BY_ID, 1, params);
    strncpy(data.query, GET_FULL_USER_DATA, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query sent\n");

    full_user_data full_user_data;
    size_t to_receive = sizeof(full_user_data);
    unsigned char *buffer = (unsigned char*)&full_user_data;
    size_t bytes_rec = receive_from_db(to_receive, buffer, sock);

    if (bytes_rec != to_receive) {
        return TOO_FEW_BYTES_RECEIVED;

    }
    if (full_user_data.user_status != SUCCESS) {
        return DATABASE_FAILURE;
    }
    if (full_user_data.user_status == SUCCESS) {
        //memcopy
        memcpy(user_data, &full_user_data, sizeof(full_user_data));
        size_t len_of_key = get_der_blob_total_length(user_data->priv_key_w_len.priv_key);
        if (len_of_key <= 0) {
           return CRYPTO_FAILURE;
        }
        user_data->priv_key_w_len.priv_key_len = len_of_key;
    }
    return user_data->user_status;
}

STATUS get_user_sym_key(const int user_id, sym_key_full *user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_int(user_id);
    query_data data = set_query_data('g', GET_SYM_KEY, 1, params);
    strncpy(data.query, GET_USER_SYM_KEY_QUERY, sizeof(data.query));
    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query sent\n");
    sym_key_full sym_key;
    size_t to_receive = sizeof(sym_key);
    unsigned char* buffer = (unsigned char*)&sym_key;
    size_t bytes_rec = receive_from_db(to_receive, buffer, sock);
    if (bytes_rec != to_receive) {
        return TOO_FEW_BYTES_RECEIVED;
    }
    if (sym_key.sym_key_status != SUCCESS) {
        return DATABASE_FAILURE;
    }

    if (sym_key.sym_key_status == SUCCESS) {
        memcpy(user_data, &sym_key, sizeof(sym_key));
    }
    return user_data->sym_key_status;
}

STATUS store_user_sym_key(const int user_id, const sym_key_full *sym_key) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_sym_key((unsigned char*)sym_key->symmetric_key);
    params[1] = create_param_sym_iv((unsigned char*)sym_key->symmetric_iv);
    params[2] = create_param_int(user_id);

    query_data data = set_query_data('p', POST_SYM_KEY, 3, params);
    strncpy(data.query, UPDATE_USER_SYM_KEY_QUERY, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query sent\n");
    STATUS post_status = read_status(sock);
    if (post_status != SUCCESS) {
        printf("Failure\n");
    }
    else printf("Success\n");

    close(sock);
    return post_status;
}

int num = 0;
STATUS get_full_user_data_by_uname(bastion_username *uname, full_user_data *user_data) {
    query_param params[MAX_PARAMS];
    params[0] = create_param_username(uname);
    params[1] = create_param_username(uname);
    query_data data{};
    data = set_query_data('g', GET_FULL_USER_BY_UNAME, 2, params);
    strncpy(data.query, GET_FULL_USER_DATA_BY_UNAME_QUERY, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    //void add_to_queue(query_data_struct* queryData)
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryDataPtr->status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    //if queryDataPtr->querydata->realtype  == blah blah blah TODO
    full_user_data full_user_data = queryDataPtr->processed_data.user_data;
    if (full_user_data.user_status != SUCCESS) {
        return DATABASE_FAILURE;
    }
    if (full_user_data.user_status == SUCCESS) {
        user_data->user_status = full_user_data.user_status;
        strncpy(user_data->username, full_user_data.username, sizeof(user_data->username));
        user_data->user_id = full_user_data.user_id;
        memcpy(user_data->priv_key_w_len.priv_key, full_user_data.priv_key_w_len.priv_key, sizeof(user_data->priv_key_w_len.priv_key));
        user_data->priv_key_w_len.priv_key_len = full_user_data.priv_key_w_len.priv_key_len;
        memcpy(user_data->enc_auth_token, full_user_data.enc_auth_token, std::size(user_data->enc_auth_token));
        user_data->secure_recovery_method = full_user_data.secure_recovery_method;
    }
    return user_data->user_status;
}

STATUS check_username_exists(bastion_username *username, bool *output) {

    query_param query_params[MAX_PARAMS];
    query_params[0] = create_param_username(username);
    query_params[1] = create_param_username(username);
    query_data data = set_query_data('g', GET_USERNAME_EXISTS, 2, query_params);
    strncpy(data.query, CHECK_IF_USERNAME_EXISTS, sizeof(data.query));


    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    //void add_to_queue(query_data_struct* queryData)
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryDataPtr->status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    *output = queryDataPtr->processed_data.username_exists;
    return queryDataPtr->status;
}

STATUS add_new_user_to_db(new_user_struct *user_data) {
    query_param query_params[MAX_PARAMS];
    query_params[0] = create_param_username(&user_data->new_username);
    query_params[1] = create_param_hash_token(user_data->new_token_hash);
    query_params[2] = create_param_asym_key(user_data->new_priv_key);
    query_params[3] = create_param_int(user_data->new_priv_key.priv_key_len);

    query_data data = set_query_data('p', INSERT_NEW_USER, 4, query_params);
    strncpy(data.query, CREATE_USER_QUERY_REG, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    return queryData.status;
}


STATUS add_new_sec_user_to_db(new_user_struct_sec *user_data) {
    query_param query_params[6];
    query_params[0] = create_param_username(&user_data->new_username);
    //
    query_params[1] = create_param_hash_token(user_data->new_token_hash);
    query_params[2] = create_param_token_enc(&user_data->new_token_encrypted);
    query_params[3] = create_param_asym_key(user_data->new_priv_key);
    query_params[4] = create_param_int(user_data->new_priv_key.priv_key_len);
    std::cout << "debgug in add new enfakjenfknafknafnafknfek ------\n";
    print_hex(user_data->seed_phrase, 32);
    query_params[5] = create_param_seed_phrase_hash(user_data->seed_phrase);

    query_data data = set_query_data('p', INSERT_NEW_USER_SEC, 6, query_params);
    strncpy(data.query, CREATE_USER_QUERY_SEC, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    return queryData.status;
}

STATUS get_seed_phrase_hash(bastion_username *username, seed_phrase_hash *seed_phrase) {
    query_param query_params[1];
    query_params[0] = create_param_username(username);

    query_data data = set_query_data('g', GET_SEED_PHRASE_HASH, 1, query_params);
    strncpy(data.query, GET_SEED_PHRASE_HASH_QUERY, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    //void add_to_queue(query_data_struct* queryData)
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryDataPtr->status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    //if queryDataPtr->querydata->realtype  == blah blah blah TODO
    if (queryDataPtr->status != SUCCESS) {
        return DATABASE_FAILURE;
    }
    if (queryDataPtr->status == SUCCESS) {
        memcpy(*seed_phrase, queryDataPtr->processed_data.hash_of_seed_phrase, sizeof(*seed_phrase));
    }

    return SUCCESS;
}


STATUS get_sym_enc_auth_token(bastion_username *username, token_sec *token_enc) {
    query_param query_params[1];
    query_params[0] = create_param_username(username);
    query_data data = set_query_data('g', GET_RAW_TOKEN_ENCRYPTED, 1, query_params);
    strncpy(data.query, GET_ENC_AUTH_TOKEN_BY_USERNAME_QUERY, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryDataPtr->status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    //if queryDataPtr->querydata->realtype  == blah blah blah TODO
    if (queryDataPtr->status != SUCCESS) {
        return DATABASE_FAILURE;
    }
    if (queryDataPtr->status == SUCCESS) {
        memcpy(*token_enc, queryDataPtr->processed_data.encrypted_raw_token, sizeof(queryDataPtr->processed_data.encrypted_raw_token));
    }

    return SUCCESS;
}


STATUS store_user_priv_key_by_username(bastion_username *username, priv_key_w_length priv_key) {
    query_param query_params[3];
    query_params[0] = create_param_asym_key(priv_key);
    query_params[1] = create_param_int(priv_key.priv_key_len);
    query_params[2] = create_param_username(username);

    query_data data = set_query_data('p', UPDATE_PRIV_KEY_BY_USERNAME, 3, query_params);
    strncpy(data.query, UPDATE_USER_PRIV_KEY_BY_USERNAME, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    return queryData.status;
}

STATUS get_client_id_from_spa_id(std::string *spa_id, int *client_id) {
    query_param query_params[1];
    query_params[0] = create_param_text((char *)spa_id->c_str());

    query_data data = set_query_data('g', GET_CLIENT_ID_BY_SPA, 1, query_params);
    strncpy(data.query, GET_CLIENT_ID_BY_SPA_ID, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    query_data_struct *queryDataPtr = &queryData;
    //void add_to_queue(query_data_struct* queryData)
    add_to_queue(queryDataPtr);

    while (queryDataPtr->is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryDataPtr->status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    //if queryDataPtr->querydata->realtype  == blah blah blah TODO
    if (queryDataPtr->status != SUCCESS) {
        return DATABASE_FAILURE;
    }
    if (queryDataPtr->status == SUCCESS) {
        *client_id = queryDataPtr->processed_data.client_id;
    }

    return SUCCESS;
}
STATUS get_device_token_by_username(bastion_username* username, apns_token *device_token_out) {
    query_param query_params[1];
    query_params[0] = create_param_username(username);

    query_data data = set_query_data('g', GET_IOS_DEVICE_TOKEN, 1, query_params);
    strncpy(data.query, GET_DEVICE_TOKEN_IOS, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    memcpy(*device_token_out, queryData.processed_data.device_token, APNS_TOKEN_SIZE);

    return queryData.status;
}

STATUS update_device_token_ios_by_username(bastion_username *username, apns_token *device_token) {
    query_param query_params[2];
    query_params[0] = create_param_username(username);
    query_params[1] = create_param_apns_token(device_token);

    query_data data = set_query_data('p', UPDATE_IOS_DEVICE_TOKEN, 2, query_params);
    strncpy(data.query, UPDATE_DEVICE_TOKEN_IOS, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    return queryData.status;
}
STATUS check_if_user_is_in_site(bastion_username* username, bool *output) {
    query_param query_params[1];
    query_params[0] = create_param_username(username);
    query_data data = set_query_data('g', GET_USERNAME_EXISTS, 1, query_params);
    strncpy(data.query, CHECK_IF_USER_EXISTS_FOR_SITE, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    while (queryData.is_ready == false) {
        std::this_thread::sleep_for(std::chrono::milliseconds(2));
    }

    STATUS process_status = queryData.status;
    if (process_status != SUCCESS) {
        return process_status;
    }

    *output = queryData.processed_data.username_exists;
    return queryData.status;
}

STATUS insert_request(const int site_id, bastion_username* username, const int approved) {

    query_param query_params[3];
    query_params[0] = create_param_int(site_id);
    query_params[1] = create_param_username(username);
    query_params[2] = create_param_int(approved);

    query_data data = set_query_data('p', UPDATE_REQUEST_DATA, 3, query_params);
    strncpy(data.query, INSERT_REQUEST_IN_DB, sizeof(data.query));

    query_data_struct queryData{};
    queryData.queryData = data;
    queryData.is_ready = false;
    add_to_queue(&queryData);
    return SUCCESS;
}