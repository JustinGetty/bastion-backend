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
    // Check that we received valid data.
    std::cout << "[THREAD] Processing" << std::this_thread::get_id() << "\n";
    if (!data) {
        std::cerr << "[ERROR] processConnectionData: Received null ConnectionData pointer." << std::endl;
        return;
    }

    // If the previous attempt already flagged failure, reset flags and exit.
    if (data->user_data.fail_this) {
        std::cerr << "[WARN] processConnectionData: User data flagged as failed for connection id: "
                  << data->connection_id << ". Aborting processing." << std::endl;
        data->user_data.being_processed = false;
        data->user_data.fail_this = false;
        return;
    }

    std::cout << "\n------------------\n"
              << "[INFO] Initiating mobile verification request for connection id: "
              << data->connection_id << "\n------------------" << std::endl;

    // Prepare the username string (initialize and ensure null-termination).
    bastion_username username = {0};
    std::strncpy(username, data->username, MAX_USERNAME_LENGTH - 1);
    username[MAX_USERNAME_LENGTH - 1] = '\0';

    if (std::strlen(username) == 0) {
        std::cerr << "[ERROR] processConnectionData: Empty username for connection id: "
                  << data->connection_id << ". Aborting processing." << std::endl;
        return;
    }
    std::cout << "[DEBUG] Username from connection data: " << username << std::endl;
    std::cout << "[INFO] Processing connection data in thread: "
              << std::this_thread::get_id() << std::endl;

    // Retrieve full user data from the database.
    full_user_data local_data = {};
    STATUS user_data_status = get_full_user_data_by_uname(&username, &local_data);
    std::cout << "[INFO] Database lookup status for username (" << username
              << "): " << user_data_status << std::endl;

    if (user_data_status != SUCCESS) {
        std::cerr << "[ERROR] Failed to retrieve full user data for username ("
                  << username << "). STATUS: " << user_data_status << std::endl;
        return;
    } else {
        std::cout << "[INFO] Retrieved full user data for username (" << username
                  << ") with user id: " << local_data.user_id << std::endl;
        std::cout << "[DEBUG] Private key (hex): " << std::endl;
        print_hex(local_data.priv_key_w_len.priv_key, local_data.priv_key_w_len.priv_key_len);
        std::cout << "[DEBUG] Encrypted auth token (hex): " << std::endl;
        print_hex(local_data.enc_auth_token, sizeof(local_data.enc_auth_token) / sizeof(local_data.enc_auth_token[0]));
    }

    // Update the connection data with the retrieved user data.
    data->user_data = local_data;

    // Try to insert the connection data into the global storage.
    ConnectionData *raw_conn_data_ptr = data.get();
    if (connection_storage.insert_connection_data(raw_conn_data_ptr) != SUCCESS) {
        std::cerr << "[ERROR] Failed to insert connection data into storage for connection id: "
                  << data->connection_id << std::endl;
        return;
    } else {
        std::cout << "[INFO] Successfully inserted connection data into storage for connection id: "
                  << data->connection_id << std::endl;
    }

    std::cout << "[INFO] Finished processing connection data for connection id: "
              << data->connection_id << std::endl;
}
