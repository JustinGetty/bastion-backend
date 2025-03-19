#include <iostream>
#include "connection_data_queue.h"
#include "databaseq.h"


void ConnectionQueue::main_server_management(bool &stop_flag)
{
    while (!stop_flag)
    {
        ConnectionData data;
        {
            std::unique_lock<std::mutex> lock(conn_mutex);
            if (isEmpty())
            {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            data = dequeue();
        }
        processConnectionData(data);
    }
}

//SERVER WORK GOES HERE
void processConnectionData(ConnectionData data)
{
    /*
    Steps:
    1. Get data from DB
    2. Send mobile verification request
    3. Add to connection storage to wait
    4. Mobile sends POST request with approval,
        endpoint grabs username, looks up data in storage, pulls it
        processes it, sends it to client
    */
    std::cout << "Processing connection data with id: " << data.connection_id << "\n";
}
