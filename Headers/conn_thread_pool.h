#ifndef CONN_THREAD_POOL_H
#define CONN_THREAD_POOL_H

#include <thread>
#include <vector>
#include "connection_data_queue.h"

class ConnThreadPool
{
private:
    std::vector<std::thread> conn_threads;
    bool stop_ = false;
    ConnectionQueue connection_queue;

    void worker();

public:
    ConnThreadPool();
    ~ConnThreadPool();

    void enqueueConnection(ConnectionData *data);
};

#endif