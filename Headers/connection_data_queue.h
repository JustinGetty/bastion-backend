// connection_data_queue.h
#pragma once

#include <bastion_data.h>
#include <array>
#include <mutex>
#include <chrono>
#include <thread>
#include <iostream>

// error codes / messages
static constexpr int GOOD_QUEUE_INIT_ERR_CODE = 0;
static constexpr int GOOD_ENQUEUE_ERR_CODE   = 0;
static constexpr int FULL_QUEUE_ERR_CODE     = 1;
static constexpr auto FULL_QUEUE_ERR  = "Queue is full\n";
static constexpr auto EMPTY_QUEUE_ERR = "Queue is empty\n";

// forward-declared in your ConnThreadPool or a helpers header:
void processConnectionData(ConnectionData* connData);

class ConnectionQueue {
public:
	ConnectionQueue();
	int  init_queue();
	void destroy_queue();
	bool isFull()  const;
	bool isEmpty() const;

	// Enqueue/dequeue raw pointers (no ownership transfer!)
	int             enqueue(ConnectionData* insert_data);
	ConnectionData* dequeue();
	ConnectionData* getFront() const;

	// loop until stop_flag becomes true, pulling each pointer and processing it
	void main_server_management(bool &stop_flag);

private:
	static constexpr int MAX_CONNECTIONS = 128;

	struct {
		int front;
		int size;
		std::array<ConnectionData*, MAX_CONNECTIONS> connections;
	} connection_queue;

	mutable std::mutex conn_mutex;
};
