#include "../Headers/conn_data_storage.h"

ConnectionDataStorage::ConnectionDataStorage() : connection_data_storage() {}

int ConnectionDataStorage::insert_connection_data(ConnectionData *data)
{
    connection_data_storage.push_back(data);
    return GOOD_INSERT;
}

// verify other side by making sure connection_id is > -1
ConnectionData *ConnectionDataStorage::get_connection_data(int connection_idenfifier)
{
    ConnectionData *data = (ConnectionData *)malloc(sizeof(ConnectionData));
    data->connection_id = -1;
    for (int i = 0; i < connection_data_storage.size(); i++)
    {
        if (connection_data_storage[i]->connection_id == connection_idenfifier)
        {
            data = connection_data_storage[i];
            return data;
        }
    }
    return data;
}