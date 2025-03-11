#include "conn_thread_pool.h"
#include <thread>

ConnThreadPool::ConnThreadPool()
{
    unsigned int num_threads = std::thread::hardware_concurrency();
    if (num_threads == 0)
        num_threads = 2;

    // create threads
    for (unsigned int i = 0; i < num_threads; i++)
    {
        conn_threads.emplace_back(&ConnThreadPool::worker, this);
    }
}

void ConnThreadPool::worker()
{
    // use main_server_management for work
    connection_queue.main_server_management(stop_);
}

void ConnThreadPool::enqueueConnection(ConnectionData *data)
{
    connection_queue.enqueue(data);
}

ConnThreadPool::~ConnThreadPool()
{
    // worker threads stop
    stop_ = true;
    for (std::thread &t : conn_threads)
    {
        if (t.joinable())
            t.join();
    }
}
