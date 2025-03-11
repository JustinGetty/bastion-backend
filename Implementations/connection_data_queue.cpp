#include "connection_data_queue.h"
#include <iostream>

ConnectionQueue::ConnectionQueue()
{
	init_queue();
}

int ConnectionQueue::init_queue()
{
	std::lock_guard<std::mutex> lock(conn_mutex);
	connections.front = 0;
	connections.size = 0;
	return GOOD_QUEUE_INIT_ERR_CODE;
}

void ConnectionQueue::destroy_queue()
{
}

bool ConnectionQueue::isFull()
{
	return connections.size == MAX_CONNECTIONS;
}

bool ConnectionQueue::isEmpty()
{
	return connections.size == 0;
}

int ConnectionQueue::enqueue(ConnectionData *insert_data)
{
	std::lock_guard<std::mutex> lock(conn_mutex);

	if (isFull())
	{
		std::cout << FULL_QUEUE_ERR;
		return FULL_QUEUE_ERR_CODE;
	}
	int rear = (connections.front + connections.size) % MAX_CONNECTIONS;
	connections.connections[rear] = insert_data;
	connections.size++;
	return GOOD_ENQUEUE_ERR_CODE;
}

ConnectionData ConnectionQueue::dequeue()
{
	std::lock_guard<std::mutex> lock(conn_mutex);

	if (isEmpty())
	{
		std::cout << EMPTY_QUEUE_ERR << std::endl;
		return ConnectionData();
	}

	ConnectionData data = *connections.connections[connections.front];
	connections.front = (connections.front + 1) % MAX_CONNECTIONS;
	connections.size--;
	return data;
}

ConnectionData ConnectionQueue::getFront()
{
	std::lock_guard<std::mutex> lock(conn_mutex);

	if (isEmpty())
	{
		std::cout << EMPTY_QUEUE_ERR;
		return ConnectionData();
	}

	return *connections.connections[connections.front];
}
