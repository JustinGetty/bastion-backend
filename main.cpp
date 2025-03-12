#include <iostream>
#include "sqldaemon.h"

task_queue_t queue;
//NEVER ADD POINTERS TO THIS

/* ----- CALLBACKS ---- */

int basic_user_get_callback(void *data, int argc, char **argv, char **colNames) {
    // argc: number of columns in the result
    // argv: array of column values (as strings)
    // colNames: array of column names

    user_data_basic *user = (user_data_basic *)data; // Cast void* to user_data_basic

    if (argc == 3) { //column count
        user->user_id = atoi(argv[0]); // Convert string to int
        strncpy(user->username, argv[1], sizeof(user->username) - 1);
        strncpy(user->timestamp, argv[2], sizeof(user->timestamp) - 1);

        user->username[sizeof(user->username) - 1] = '\0';
        user->timestamp[sizeof(user->timestamp) - 1] = '\0';
        user->status =  0;
    }

    return 0; // Returning 0 continues execution
}

void task_queue_init(task_queue_t *q) {
    q->front = 0;
    q->rear = 0;
    q->count = 0;
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond_not_empty, NULL);
    pthread_cond_init(&q->cond_not_full, NULL);
}

void task_queue_push(task_queue_t *q, int client_sock) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == TASK_QUEUE_CAPACITY) {
        pthread_cond_wait(&q->cond_not_full, &q->mutex);
    }
    q->task[q->rear].client_socket = client_sock;
	//add to end, wrap to 0 if needed - circle queue
    q->rear = (q->rear + 1) % TASK_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->cond_not_empty);
    pthread_mutex_unlock(&q->mutex);
}

int task_queue_pop(task_queue_t *q) {
    pthread_mutex_lock(&q->mutex);
    while (q->count == 0) {
        pthread_cond_wait(&q->cond_not_empty, &q->mutex);
    }
    int client_socket = q->task[q->front].client_socket;
	//add to end, wrap to 100 if needed - circle queue
    q->front = (q->front + 1) % TASK_QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->cond_not_full);
    pthread_mutex_unlock(&q->mutex);
    return client_socket;
}

//eventually this is going to need to switch between POST/GET, either send results or errmsg
void *worker_thread(void *arg) {
    sqlite3 *db;
    if (sqlite3_open(DATABASE, &db) != SQLITE_OK) {
        fprintf(stderr, "Thread %lu: Cannot open database: %s\n",
                pthread_self(), sqlite3_errmsg(db));
        pthread_exit(NULL);
    }

    printf("Thread %lu: Opening database %s\n", pthread_self(), DATABASE);
	//lets get this closer to actual max query size
   //also free this after use lmao???
    char buffer[4096];


    while (1) {
        int client_sock = task_queue_pop(&queue);
        user_data_basic user;
        memset(&user, 0, sizeof(user));

        printf("Client sock in worker = %d\n", client_sock);
        memset(buffer, 0, sizeof(buffer));

        ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            close(client_sock);
            continue;
        }
        printf("Thread %lu received query: %s\n", pthread_self(), buffer);

        char *errMsg = NULL;
        int rc = sqlite3_exec(db, buffer, basic_user_get_callback, &user, &errMsg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error: %s\n", errMsg);
			int err = -1;
            send(client_sock, errMsg, sizeof(int), 0);
            sqlite3_free(errMsg);
        } else {
            printf("Query executed successfully\n");
            printf("User ID: %d\n", user.user_id);
            printf("Username: %s\n", user.username);
            printf("Timestamp: %s\n", user.timestamp);

			char buff[] = "Success";
            //send full struct here, add success parameter to struct
            send(client_sock, &user, sizeof(user), 0);
        }
        close(client_sock);
    }


	//again this will prob never be hit
    sqlite3_close(db);
    return NULL;
}


// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

int main() {
    task_queue_init(&queue);

    pthread_t threads[THREAD_POOL_SIZE];
    for (int i = 0; i < THREAD_POOL_SIZE; i++) {
        if (pthread_create(&threads[i], NULL, worker_thread, NULL) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }
    printf("Thread pool of %d worker threads created.\n", THREAD_POOL_SIZE);

    int server_fd, client_sock;
    struct sockaddr_un address;
    socklen_t addrlen = sizeof(address);

    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    unlink(SQLITE_DAEMON_SOCKET_PATH);

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SQLITE_DAEMON_SOCKET_PATH, sizeof(address.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    //increase backlog with scale, can handle 64 conns in backlog rn
    if (listen(server_fd, 64) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("SQLite daemon listening on UNIX socket %s...\n", SQLITE_DAEMON_SOCKET_PATH);

    while (1) {
        client_sock = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (client_sock < 0) {
            perror("accept failed");
            continue;
        }
        printf("Client sock = %d\n", client_sock);
        task_queue_push(&queue, client_sock);
    }

    //theoretically never reached, should def make a more graceful closing lollll
    close(server_fd);
    unlink(SQLITE_DAEMON_SOCKET_PATH);
    return 0;
}