#ifndef DATABASE_HEAD_H
#define DATABASE_HEAD_H

#include <sys/socket.h>
#include <bastion_data.h>


#define THREAD_POOL_SIZE 3
#define TASK_QUEUE_CAPACITY 10000



typedef struct {
	query_data_struct *queryDataStruct;
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
void task_queue_push(task_queue_t *q, query_data_struct* queryData);
query_data_struct* task_queue_pop(task_queue_t *q);
void *worker_thread(void *arg);
void setup_threads();
void add_to_queue(query_data_struct* queryData);




#endif
