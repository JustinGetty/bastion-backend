#ifndef CONN_DATA_STORAGE_H
#define CONN_DATA_STORAGE_H

#include "custom_data.h"
#include <iostream>
#include <vector>

#define GOOD_INSERT 0
#define BAD_INSERT -1
#define GOOD_RETRIEVAL 0
#define BAD_RETRIEVAL -1
#define GOOD_INIT 0
#define BAD_INIT -1

class ConnectionDataStorage
{
private:
    std::vector<ConnectionData *> connection_data_storage;

public:
    ConnectionDataStorage();
    int insert_connection_data(ConnectionData *data);
    ConnectionData *get_connection_data(int connection_identifier);
};

#endif