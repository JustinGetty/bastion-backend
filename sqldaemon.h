#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#define SOCKET_PATH "/tmp/sqlite_daemon.sock"
#define THREAD_POOL_SIZE 10
#define TASK_QUEUE_CAPACITY 100
#define DATABASE "/infinite/Projects/NoPass/Server/Databases/ProdDatabase"

typedef struct {
	int client_socket;
} task_t;

typedef struct {
	task_t task[TASK_QUEUE_CAPACITY];
	int front;
	int rear;
	int count;
	pthread_mutex_t mutex;
	pthread_cond_t cond_not_empty;
	pthread_cond_t cond_not_full;
} task_queue_t;


void task_queue_init(task_queue_t *q);
void task_queue_push(task_queue_t *q, int client_sock);
int task_queue_pop(task_queue_t *q);
void *worker_thread(void *arg);


#ifdef __cplusplus
}
#endif
