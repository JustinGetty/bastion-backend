#include "../Headers/databaseq.h"

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

STATUS get_basic_user_by_id(int userID, user_data_basic *user_data)
{
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return DATABASE_FAILURE;
    }
    query_param params[MAX_PARAMS];
    params[0] = create_param_int(userID);

    query_data data = set_query_data('g', GET_BASIC_USER_BY_ID, 1, params);
    strncpy(data.query, GET_BASIC_USER_QUERY, sizeof(data.query));

    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    read(sock, user_data, sizeof(user_data_basic));
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
        return DATABASE_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_text(user_data.username);
    query_data data = set_query_data('p', POST_BASIC_USER, 2, params);

    strncpy(data.query, POST_BASIC_USER_QUERY, sizeof(data.query));
    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    STATUS post_status;
    read(sock, &post_status, sizeof(STATUS));
    close(sock);
    return post_status;
}

//does not yet contain asym_key
STATUS post_full_user_data(full_user_data_enc user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return DATABASE_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_text(user_data.username);
    params[1] = create_param_hash_token(user_data.enc_auth_token);

    //fill data
    query_data data = set_query_data('p', POST_FULL_NEW_USER, 3, params);

    strncpy(data.query, POST_FULL_NEW_USER_QUERY, sizeof(data.query));
    printf("query: %s\n", POST_FULL_NEW_USER_QUERY);
    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    STATUS post_status;
    read(sock, &post_status, sizeof(STATUS));
    close(sock);
    return post_status;
}

STATUS store_token_hash(const int user_id, const token_hash token_hash_, const size_t hash_len) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return DATABASE_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_hash_token(token_hash_);
    params[1] = create_param_int(user_id);
    query_data data = set_query_data('p', POST_AUTH_TOKEN, 2, params);
    strncpy(data.query, UPDATE_USER_AUTH_TOKEN_BY_ID, sizeof(data.query));
    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");
    STATUS post_status;
    read(sock, &post_status, sizeof(STATUS));
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
        return DATABASE_FAILURE;
    }

    query_param params[MAX_PARAMS];
    params[0] = create_param_int(id);
    query_data data = set_query_data('g', GET_AUTH_TOKEN, 1, params);
    strncpy(data.query, GET_AUTH_TOKEN_BY_ID, sizeof(data.query));

    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    hash_token_struct token_hash;

    read(sock, &token_hash, sizeof(hash_token_struct));
    if (token_hash.status_ == SUCCESS) {
        memcpy(hash_out, token_hash.token_hash_, HASH_SIZE);
    }

    return token_hash.status_;
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
