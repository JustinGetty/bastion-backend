#include "connection_data_queue.h"

ConnectionQueue::ConnectionQueue() {
    init_queue();
}

int ConnectionQueue::init_queue() {
    std::lock_guard<std::mutex> lock(conn_mutex);
    connection_queue.front = 0;
    connection_queue.size  = 0;
    for (auto &ptr : connection_queue.connections) {
        ptr = nullptr;
    }
    return GOOD_QUEUE_INIT_ERR_CODE;
}

void ConnectionQueue::destroy_queue() {
    std::lock_guard<std::mutex> lock(conn_mutex);
    for (auto &ptr : connection_queue.connections) {
        ptr = nullptr;
    }
    connection_queue.size = 0;
}

bool ConnectionQueue::isFull() const {
    return connection_queue.size == MAX_CONNECTIONS;
}

bool ConnectionQueue::isEmpty() const {
    return connection_queue.size == 0;
}

int ConnectionQueue::enqueue(ConnectionData* insert_data) {
    std::lock_guard<std::mutex> lock(conn_mutex);
    if (isFull()) {
        std::cerr << FULL_QUEUE_ERR;
        return FULL_QUEUE_ERR_CODE;
    }
    int rear = (connection_queue.front + connection_queue.size) % MAX_CONNECTIONS;
    connection_queue.connections[rear] = insert_data;
    ++connection_queue.size;
    return GOOD_ENQUEUE_ERR_CODE;
}

ConnectionData* ConnectionQueue::dequeue() {
    std::lock_guard<std::mutex> lock(conn_mutex);
    if (isEmpty()) {
        //std::cout << EMPTY_QUEUE_ERR;
        return nullptr;
    }
    ConnectionData* data = connection_queue.connections[connection_queue.front];
    connection_queue.connections[connection_queue.front] = nullptr;
    connection_queue.front = (connection_queue.front + 1) % MAX_CONNECTIONS;
    --connection_queue.size;
    return data;
}

ConnectionData* ConnectionQueue::getFront() const {
    std::lock_guard<std::mutex> lock(conn_mutex);
    if (isEmpty()) {
        //std::cout << EMPTY_QUEUE_ERR;
        return nullptr;
    }
    return connection_queue.connections[connection_queue.front];
}