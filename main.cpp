#include <iostream>
#include "sqldaemon.h"
// TIP To <b>Run</b> code, press <shortcut actionId="Run"/> or click the <icon src="AllIcons.Actions.Execute"/> icon in the gutter.

int main() {
    task_queue_t queue;
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

    unlink(SOCKET_PATH);

    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, SOCKET_PATH, sizeof(address.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    //increase backlog with scale, can handle 64 conns in backlog rn
    if (listen(server_fd, 64) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }
    printf("SQLite daemon listening on UNIX socket %s...\n", SOCKET_PATH);

    while (1) {
        client_sock = accept(server_fd, (struct sockaddr *)&address, &addrlen);
        if (client_sock < 0) {
            perror("accept failed");
            continue;
        }
        task_queue_push(&queue, client_sock);
    }

    //theoretically never reached, should def make a more graceful closing lollll
    close(server_fd);
    unlink(SOCKET_PATH);
    return 0;
}