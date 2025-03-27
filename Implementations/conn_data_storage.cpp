#include "../Headers/conn_data_storage.h"

std::vector<ConnectionData *> ConnectionDataStorage::connection_data_storage;
ConnectionDataStorage::ConnectionDataStorage() {}

STATUS ConnectionDataStorage::insert_connection_data(ConnectionData *data)
{
    std::lock_guard<std::mutex> lock(mtx);
    try {
        connection_data_storage.push_back(data);
    } catch (const std::exception& e) {
        std::cerr << "Error inserting data into data storage: " << e.what() << "\n";
        return CONNECTION_STORAGE_INSERTED_FAILURE;
    }
    std::cout << "Connection added to storage; ID: " << data->connection_id << "\n";
    return SUCCESS;
}

// verify other side by making sure connection_id is > -1
ConnectionData *ConnectionDataStorage::get_connection_data(int connection_idenfifier)
{
    std::lock_guard<std::mutex> lock(mtx);
    ConnectionData data{};
    data.connection_id = -1;
    ConnectionData* data_ptr = &data;
    for (int i = 0; i < connection_data_storage.size(); i++)
    {
        if (connection_data_storage[i]->connection_id == connection_idenfifier)
        {
            data_ptr = connection_data_storage[i];
            std::cout << "Got connection from storage with id: " << data_ptr->connection_id << "\n";
            return data_ptr;
        }
    }
    std::cout << "Failed to get connection with id: " << connection_idenfifier << "\n";
    return data_ptr;
}