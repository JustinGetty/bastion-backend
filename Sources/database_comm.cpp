#include "../Headers/databaseq.h"

/*
void send_post_query(const char *query)
{
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un server_addr;

    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, POST_SOCKET_PATH);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Connection failed\n");
        exit(1);
    }

    send(sock, query, strlen(query), 0);

    // read back status here
    /*
    char response[1024];
    read(sock, response, sizeof(response));
    printf("Response: %s\n", response);

close(sock);
}
*/

STATUS get_basic_user_by_id(int userID, user_data_basic *user_data)
{

    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("Socket fucked\n");
    }
    printf("Socket: %d\n", sock);
    struct sockaddr_un server_addr;

    server_addr.sun_family = AF_UNIX;
    strcpy(server_addr.sun_path, SQLITE_DAEMON_SOCKET_PATH);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        printf("Connection failed\n");
        return WEBSOCKET_FAILURE;
    }

    //needs to be prepared statements!!!
    char query[MAX_GET_QUERY];
    snprintf(query, sizeof(query), "SELECT user_id, username, timestamp FROM user WHERE user_id = %d", userID);

    printf("query: %s\n", query);
    printf("Query Sent\n");
    send(sock, query, strlen(query), 0);

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
STATUS post_basic_user_data(user_data_basic user_data) {

}


int main()
{
    user_data_basic user_data;
    STATUS result = get_basic_user_by_id(1, &user_data);
    printf("Status: %d, Username: %s\n", user_data.status, user_data.username);

    printf("Finished\n");
    //printf("UserName: %s\n", user_data->username);

    return 0;
}
