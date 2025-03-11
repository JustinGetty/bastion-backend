#include "sqldaemon.h"

task_queue_t queue;  

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

	//lets get this closer to actual max query size
    char buffer[4096];  
    while (1) {
        int client_sock = task_queue_pop(&queue);
        memset(buffer, 0, sizeof(buffer));

        ssize_t bytes_read = read(client_sock, buffer, sizeof(buffer) - 1);
        if (bytes_read <= 0) {
            close(client_sock);
            continue;
        }
        printf("Thread %lu received query: %s\n", pthread_self(), buffer);
		/*
		 * add back after testing and implement

        char *errMsg = NULL;
        int rc = sqlite3_exec(db, buffer, NULL, NULL, &errMsg);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQLite error: %s\n", errMsg);
			int err = -1;
            send(client_sock, err, sizeof(int), 0);
            sqlite3_free(errMsg);
        } else {
            printf("Query executed successfully\n");
			int succ = 0;
            send(client_sock, succ, sizeof(int), 0);
        }
		*/
        close(client_sock);
    }


	//again this will prob never be hit
    sqlite3_close(db);
    return NULL;
}


