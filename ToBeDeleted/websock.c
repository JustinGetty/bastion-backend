#include <libwebsockets.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>    
#include <unistd.h>  
#include <sys/stat.h> 

/*
TODO:

- lws wsi maintains state of connection, send this to thread to fetch db info, then send back to lws with lws_callback_on_writable(data->wsi);
*/

#define MAX_JSON 4096

struct client_signin_data {
	struct lws *wsi;
	char json_data[MAX_JSON];
};

static int interrupted = 0;
static void sigint_handler(int sig) {
    interrupted = 1;
}

void initdaemon()
{
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		perror("First fork failed");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	if (setsid() < 0) {
		perror("setsid failed");
		exit(EXIT_FAILURE);
	}

	pid = fork();
	if (pid < 0) {
		perror("Second fork failed");
		exit(EXIT_FAILURE);
	}
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	int fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, STDIN_FILENO);
		dup2(fd, STDOUT_FILENO);
		dup2(fd, STDERR_FILENO);
		close(fd);
	}

	chdir("/");
	umask(0);
}

//in received data (data in), len is length of that
static int callback_echo(struct lws *wsi,
                         enum lws_callback_reasons reason,
                         void *user, void *in, size_t len)
{
    switch (reason) {

        case LWS_CALLBACK_ESTABLISHED: {
            lwsl_user("Connection established\n");
			printf("WE IN");
            break;
		}

        case LWS_CALLBACK_RECEIVE: {
			//log and cast to char*
            lwsl_user("Received: %s\n", (char *)in);
			printf("Message Received: %s\n", (char *)in);
			//LWS PRE is metadata
            unsigned char buf [LWS_PRE + 1024];
            size_t n = len < 1024 ? len : 1024;
			//skip LWS_PRE bytes and copy revieved data into buffer
            memcpy(&buf[LWS_PRE], in, n);
			//send it
            int m = lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
            if (m < (int)n)
			{
                lwsl_err("ERROR writing to socket\n");
				printf("ERROR writing to socket\n");
			}
            break;
        }

        case LWS_CALLBACK_CLOSED:
            lwsl_user("Connection closed\n");
            break;

        default:
            break;
    }
    return 0;
}

void *signin_auth_thread(void *arg) 
{
	struct client_signin_data *data = (struct client_signin_data *)arg;
	printf("Thread spawned");
	//CALL DB OBJ
	//go sign in the user
	return NULL;
}

static int callback_signin_auth(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *rec_data, size_t len)
{
	switch (reason) {
		case LWS_CALLBACK_ESTABLISHED:
			lwsl_user("Connection Established");
			printf("Connection Established");
			break;

		case LWS_CALLBACK_RECEIVE: {
			lwsl_user("Username Received: %s\n", (char *)rec_data);
			printf("Username Received: %s\n", (char *)rec_data);

			//parse request fields (i.e name, email, etc.)

	
			//here make request to phone verify
			//set this to wait and make a new thread to instantiate the db conn OBJ
			
            unsigned char buf [LWS_PRE + 1024];
            size_t n = len < 1024 ? len : 1024;
			//skip LWS_PRE bytes and copy revieved data into buffer
            memcpy(&buf[LWS_PRE], rec_data, n);

			//send back requested data in JSON
			int m = lws_write(wsi, &buf[LWS_PRE], n, LWS_WRITE_TEXT);
			if (m < (int)n)
			{
				lwsl_err("ERROR writing to socket\n");
				printf("ERROR writing to socket\n");
			}
			break;
		}

	}
}

//callback function should create new thread for each connection, would bottleneck if not
//needs AT LEAST same # of threads as DB daemon

static struct lws_protocols protocols[] = {
    {
        "echo-protocol",
        callback_echo,
        0,            //sesh data size
        1024,         //max frame size
    },
	{
		"signin-auth-protocol",
		callback_signin_auth,
		0,
		1024,
	},
    { NULL, NULL, 0, 0 } //terminator
};

int main(void)
{
	initdaemon();
    struct lws_context_creation_info info;
    struct lws_context *context;

	//shutdown here, eventually delete
    signal(SIGINT, sigint_handler);
    memset(&info, 0, sizeof(info));
    
    info.port = 8443;  
    info.protocols = protocols;

	//force http for dev NOT PRODDDDDD
	info.alpn = "http/1.1";

    info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
	info.fd_limit_per_thread = 1024;
    
    //info.ssl_cert_filepath = "/infinite/Projects/NoPass/Server/certs/server-cert.pem";
    //info.ssl_private_key_filepath = "/infinite/Projects/NoPass/Server/certs/server-key.pem";
   
   //add back in prod IMPORTANT	
 //   info.ssl_ca_filepath = "/etc/ssl/certs/ca-certificates.crt";
 //   info.options |= LWS_SERVER_OPTION_REQUIRE_VALID_OPENSSL_CLIENT_CERT;
    
    info.ssl_cipher_list = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    
    context = lws_create_context(&info);
    if (!context) {
        lwsl_err("lws_create_context failed\n");
        return 1;
    }
    lwsl_user("Secure WebSocket server started on port %d\n", info.port);
    
    while (!interrupted)
        lws_service(context, 1000);

    lws_context_destroy(context);
    return 0;
}


