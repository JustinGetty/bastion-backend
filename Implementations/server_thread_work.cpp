#include <iostream>
#include "connection_data_queue.h"
#include "conn_data_storage.h"
#include "databaseq.h"
#include "cryptography.h"


void processConnectionData(std::unique_ptr<ConnectionData> data);
ConnectionDataStorage connection_storage;

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
    1. Send mobile verification request
    2. Get data from DB
    3. Add to connection storage to wait
    4. Mobile sends POST request with approval,
        endpoint grabs username, looks up data in storage, pulls it
        processes it, sends it to client
    */

    //send to mobile daemon here
    /*
     *SEND CONNECTION ID SO WHEN THE USER SENDS BACK POST WITH THEIR RESPONSE IT CAN BE FOUND IN CONN STORAGE
    std::cout << "\n------------------\n";
    std::cout << "Pretending to send request to mobile blah blah blah\n";
    std::cout << "\n------------------\n";
    if (!data) {
        std::cout << "No data to proccess\n";
    }

    full_user_data local_data;
    //TODO remove hardcoding
    bastion_username username;
    if (!data) {
        std::cout << "No data to process\n";
        return;
    }

    std::strncpy(username, data->username, MAX_USERNAME_LENGTH - 1);
    //TODO why is this being hit twice in some cases?
    std::cout << "Username in work thread: " << data->username << "\n";
    username[MAX_USERNAME_LENGTH - 1] = '\0';
    std::cout << "Username in work thread as username: " << username << "\n";
    bastion_username* uname_ptr = &username;
    std::cout << "Username in work thread as username ptr: " << *uname_ptr << "\n";
    std::cout << "\n------------------\n";
    std::cout << "Doing work!\n";
    STATUS user_data_status = get_full_user_data_by_uname(uname_ptr, &local_data);
    std::cout << "Work status: " << user_data_status << "\n";
    std::cout << "\n------------------\n";

    if (user_data_status != SUCCESS) {
        std::cerr << "Error: " << user_data_status << "\n";
    }
    if (user_data_status == SUCCESS) {
        std::cout << "Got user id: " << local_data.user_id << " from DB!\n";
        std::cout << "thread id: " << std::this_thread::get_id() << "\n";
        std::cout << "Processing connection data with id: " << data->connection_id << "\n";
        std::cout << "Username: " << local_data.username << "\n";
    }

    data->user_data = local_data;

    //get unique ptrrr
    ConnectionData *raw_conn_data_ptr = data.get();
    //add to storage queue
    if (connection_storage.insert_connection_data(raw_conn_data_ptr) != SUCCESS) {
        std::cout << "could not insert connection data ahhh\n";
        return;
    }

    //works only for valid connections, should not be ran with stress test
    /*
    ConnectionData *data_from_storage = connection_storage.get_connection_data(data->connection_id);
    std::cout << "Data pulled from storage with id: " << data_from_storage->connection_id << "\n";
    */



    //this breaks client connection - good thing
    std::cout << "Client connection broken, have a good day\n";
}
