#ifndef CONNECTION_DATA_QUEUE_H
#define CONNECTION_DATA_QUEUE_H

#include <iostream>
#include <App.h>
#include <mutex>
#include <bastion_data.h>

#define MAX_CONNECTIONS 20

#define SUCC_ENQUEUE "Data inserted successfully!\n"
#define SUCC_DEQUEUE "Data dequeued successfully!\n"

#define FULL_QUEUE_ERR "ERROR: Queue is full!\n"
#define EMPTY_QUEUE_ERR "ERROR: Queue is empty!\n"

#define FULL_QUEUE_ERR_CODE -3
#define GOOD_ENQUEUE_ERR_CODE 0
#define BAD_QUEUE_INIT_ERR_CODE -1
#define GOOD_QUEUE_INIT_ERR_CODE 0

typedef struct
{
	std::array<std::unique_ptr<ConnectionData>, MAX_CONNECTIONS> connections;
	int front;
	int size;
} Queue;

class ConnectionQueue
{
private:
	Queue connection_queue;
	std::mutex conn_mutex;

public:
	ConnectionQueue();
	int init_queue();
	void destroy_queue();
	bool isFull();
	bool isEmpty();
	int enqueue(std::unique_ptr<ConnectionData> insert_data);

	std::unique_ptr<ConnectionData> dequeue();
	ConnectionData getFront();

	void main_server_management(bool &stop_flag);
};

// Dummy processing function; replace with your own logic.
void processConnectionData(const ConnectionData data);

#endif
