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
    printf("Here 1\n");
    std::strcpy(param.data.username_val, *username);
    printf("Here 2\n");
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
            fprintf(stderr, "ERROR RECEIVING\n");
            return TOO_FEW_BYTES_RECEIVED;
        }
        if (received == 0) {
            break;
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

STATUS store_token_hash(const int user_id, const token_hash token_hash_, const size_t hash_len) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_hash_token(token_hash_);
    params[1] = create_param_int(user_id);
    query_data data = set_query_data('p', POST_AUTH_TOKEN, 2, params);
    strncpy(data.query, UPDATE_USER_AUTH_TOKEN_BY_ID, sizeof(data.query));
    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query Sent\n");
    STATUS post_status = read_status(sock);
    if (post_status != SUCCESS) {
        printf("FAilure");
    }
    else
        printf("SUCCESS\n");
    close(sock);
    return post_status;
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
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_int(user_id);

    query_data data = set_query_data('g', GET_ASYM_PRIV_KEY, 1, params);
    strncpy(data.query, GET_USER_PRIVATE_KEY_BY_ID, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query sent\n");

    priv_key_struct priv_key;
    unsigned char *buffer = (unsigned char *)&priv_key;

    size_t to_receive = sizeof(priv_key_struct);
    int bytes_rec = receive_from_db(to_receive, buffer, sock);

    if (bytes_rec != to_receive) {
        fprintf(stderr, "ERROR RECEIVING");
        return TOO_FEW_BYTES_RECEIVED;
    }

    if (priv_key.priv_key_status != SUCCESS) {
        return DATABASE_FAILURE;
    }

    if (priv_key.priv_key_status == SUCCESS) {
        memcpy(priv_key_full, priv_key.priv_key, sizeof(priv_key.priv_key));
        priv_key_full->priv_key_len = priv_key.priv_key_len;
        size_t len = get_der_blob_total_length(priv_key.priv_key);
        if (len > 0) {
            priv_key_full->priv_key_len = len;
        } else {
            return DATABASE_FAILURE;
        }
    }
    return priv_key.priv_key_status;
}
STATUS store_user_private_key(const int user_id, priv_key_w_length *priv_key_full) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_asym_key(*priv_key_full);
    params[1] = create_param_int(user_id);

    query_data data = set_query_data('p', POST_ASYM_PRIV_KEY, 2, params);
    strncpy(data.query, UPDATE_USER_PRIV_KEY_BY_ID, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query Sent\n");

    STATUS post_status = read_status(sock);
    if (post_status != SUCCESS) {
        printf("Failure\n");
    }
    else printf("Success\n");

    close(sock);
    return post_status;

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
        printf("Here\n");
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


STATUS get_full_user_data_by_uname(bastion_username *uname, full_user_data *user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return CONNECTION_TO_DB_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_username(uname);
    query_data data{};
    data = set_query_data('g', GET_FULL_USER_BY_UNAME, 1, params);
    strncpy(data.query, GET_FULL_USER_DATA_BY_UNAME_QUERY, sizeof(data.query));

    STATUS send_status = send_query(sock, data);
    if (send_status != SUCCESS) {
        return send_status;
    }
    printf("Query sent\n");

    printf("Here3\n");
    full_user_data full_user_data;
    size_t to_receive = sizeof(full_user_data);
    unsigned char *buffer = (unsigned char*)&full_user_data;
    size_t bytes_rec = receive_from_db(to_receive, buffer, sock);

    printf("Here4\n");
    if (bytes_rec != to_receive) {
        printf("Error1\n");
        return TOO_FEW_BYTES_RECEIVED;
    }
    if (full_user_data.user_status != SUCCESS) {
        printf("Error2\n");
        return DATABASE_FAILURE;
    }
    if (full_user_data.user_status == SUCCESS) {
        printf("Error3\n");
        //memcopy
        //issue here is memcopying wit a c++ value
        /*
         *TODO
         *fix this tomorrow
         *issue possibly in ConnectionData with std::string username
         *I switched to char[] to test
         */
        //memcpy(user_data, &full_user_data, sizeof(full_user_data));
        user_data->user_status = full_user_data.user_status;
        strncpy(user_data->username, full_user_data.username, sizeof(user_data->username));
        user_data->user_id = full_user_data.user_id;
        printf("Here4.5\n");
        size_t len_of_key = get_der_blob_total_length(user_data->priv_key_w_len.priv_key);
        if (len_of_key <= 0) {
            return CRYPTO_FAILURE;
        }
        printf("Here\n");
        user_data->priv_key_w_len.priv_key_len = len_of_key;
    }
    printf("Here5\n");
    return user_data->user_status;
}

//should only exist for the purpose of testing, DEF remove in prod!!!
/*
int main()

{
    token_hash out_token_hash;
    STATUS get_status = get_token_hash(1, out_token_hash, TOKEN_SIZE);
    if (get_status != SUCCESS) {
        printf("Failure");
        return -1;
    }
    for (int i = 0; i < HASH_SIZE; i++) {
        printf("%02x", out_token_hash[i]);
    }
    printf("\n");
    return 0;
}
*/
