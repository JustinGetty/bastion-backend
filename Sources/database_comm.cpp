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

STATUS get_basic_user_by_id(int userID, user_data_basic *user_data)
{
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return DATABASE_FAILURE;
    }
    //could be redundant stack usage, maybe string copy directly into data struct
    query_data data;
    data.type = 'g';
    data.real_type = GET_BASIC_USER_BY_ID;
    data.num_params = 1;
    query_param first_param;
    first_param.type = PARAM_INT;
    first_param.data.int_val = userID;
    data.params[0] = first_param;
    strncpy(data.query, GET_BASIC_USER_QUERY, sizeof(data.query));

    printf("query: %s\n", GET_BASIC_USER_QUERY);
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

    query_data data;
    data.type = 'p';
    data.real_type = POST_BASIC_USER;
    data.num_params = 2;
    query_param first_param;
    first_param.type = PARAM_TEXT;
    strncpy(first_param.data.text_val, user_data.username, sizeof(first_param.data.text_val));
    data.params[0] = first_param;

    strncpy(data.query, POST_BASIC_USER_QUERY, sizeof(data.query));
    printf("query: %s\n", POST_BASIC_USER_QUERY);
    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    STATUS post_status;
    read(sock, &post_status, sizeof(STATUS));
    close(sock);
    return post_status;
}

STATUS post_full_user_data(full_user_data_enc user_data) {
    int sock = connect_to_database_daemon();
    if (sock < 0) {
        return DATABASE_FAILURE;
    }

    //fill data
    query_data data;
    data.type = 'p';
    data.real_type = POST_FULL_NEW_USER;
    data.num_params = 3;
    query_param first_param; query_param second_param; query_param third_param;

    first_param.type = PARAM_TEXT; second_param.type = PARAM_BLOB; third_param.type = PARAM_BLOB;
    strncpy(first_param.data.text_val, user_data.username, sizeof(first_param.data.text_val));
    data.params[0] = first_param;

    //absolutely no way this works
    strncpy((char *)second_param.data.blob_val, (const char*)user_data.enc_auth_token, sizeof(second_param.data.blob_val));
    data.params[1] = second_param;

    //if this works I am going to believe in religion
    strncpy((char *)third_param.data.blob_val, (const char*)user_data.enc_auth_token, sizeof(third_param.data.blob_val));
    data.params[2] = third_param;

    strncpy(data.query, POST_FULL_NEW_USER_QUERY, sizeof(data.query));
    printf("query: %s\n", POST_FULL_NEW_USER_QUERY);
    send(sock, &data, sizeof(query_data), 0);
    printf("Query Sent\n");

    STATUS post_status;
    read(sock, &post_status, sizeof(STATUS));
    close(sock);
    return post_status;
}


//should only exist for the purpose of testing, DEF remove in prod!!!
int main()
{
    user_data_basic post_user_data;
    strncpy(post_user_data.username, "test_user2", sizeof(post_user_data.username));
    STATUS post_status = post_basic_user_data(post_user_data);
    printf("Status: %d\n", post_status);

    user_data_basic user_data;
    STATUS result = get_basic_user_by_id(1, &user_data);
    printf("Status: %d, Username: %s\n", user_data.status, user_data.username);

    printf("Finished\n");
    //printf("UserName: %s\n", user_data->username);

    return 0;
}
