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

STATUS get_basic_user_by_id(int userID, user_data_struct &user_data)
{

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	struct sockaddr_un server_addr;

	server_addr.sun_family = AF_UNIX;
	strcpy(server_addr.sun_path, GET_SOCKET_PATH);

	if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
	{
		printf("Connection failed\n");
		return WEBSOCKET_FAILURE;
	}

	char query[MAX_GET_QUERY];
	snprintf(query, sizeof(query), "SELECT user_id, username, timestamp FROM user WHERE user_id = %d", userID);

	send(sock, query, strlen(query), 0);

	char raw_response_data[1024];
	read(sock, raw_response_data, sizeof(raw_response_data));
	printf("Response: %s\n", raw_response_data);

	close(sock);
	return SUCCESS;
}

full_user_data_enc get_full_enc_user_by_id(int userID) {}
STATUS post_basic_user_data(user_data_struct user_data) {}
STATUS post_full_user_data(full_user_data_enc user_data) {}

int main()
{
	char query[MAX_GET_QUERY];
	while (1)
	{
		printf(">>>");
		if (fgets(query, 25, stdin) == NULL)
		{
			printf("\n");
			break;
		}
		query[strcspn(query, "\n")] = '\0';

	}
	return 0;
}
