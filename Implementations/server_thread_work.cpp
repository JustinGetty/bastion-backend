#include <iostream>
#include "connection_data_queue.h"
#include "databaseq.h"
#include "cryptography.h"

int work_done = 0;
void processConnectionData(std::unique_ptr<ConnectionData> data);

void ConnectionQueue::main_server_management(bool &stop_flag)
{
    while (!stop_flag)
    {
        std::unique_ptr<ConnectionData> data;
        {
            //std::unique_lock<std::mutex> lock(conn_mutex);
            if (isEmpty())
            {
                //lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
                continue;
            }
            data = dequeue();

        }
        processConnectionData(std::move(data));
    }
}

//SERVER WORK GOES HERE
void processConnectionData(std::unique_ptr<ConnectionData> data) {
    /*
    Steps:
    1. Get data from DB
    2. Send mobile verification request
    3. Add to connection storage to wait
    4. Mobile sends POST request with approval,
        endpoint grabs username, looks up data in storage, pulls it
        processes it, sends it to client
    */
    if (!data) {
        std::cout << "No data to proccess\n";
    }

    full_user_data local_data;
    bastion_username username;
    //std::strncpy(username, data->username.c_str(), MAX_USERNAME_LENGTH - 1);
    bastion_username* uname_ptr = &username;
    std::cout << "\n------------------\n";
    std::cout << "Doing work!\n";
    std::cout << "Finished working on: " << work_done << "\n";
    std::cout << "\n------------------\n";
    work_done += 1;


    /*
     *REMOVING THIS TO SEE WHICH DAEMON IS FUCKING UP
    STATUS user_data_status = get_full_user_data_by_uname(uname_ptr, &local_data);
    if (user_data_status != SUCCESS) {
        std::cerr << "Error: " << user_data_status << "\n";
    }
    if (user_data_status == SUCCESS) {
        std::cout << "Got user id: " << local_data.user_id << " from DB!\n";
        std::cout << "thread id: " << std::this_thread::get_id() << "\n";
        std::cout << "Processing connection data with id: " << data->connection_id << "\n";
        std::cout << "Username: " << local_data.username << "\n";
    }
    */

    //this breaks client connection - good thing
}
