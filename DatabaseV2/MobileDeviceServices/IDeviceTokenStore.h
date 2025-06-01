//
// Created by root on 5/20/25.
//

#ifndef IDEVICETOKENSTORE_H
#define IDEVICETOKENSTORE_H
#include <bastion_data.h>

struct IDeviceTokenStore {

    virtual void insertOrUpdateToken(const std::string& uname, const ios_device_token& token) = 0;
    virtual ~IDeviceTokenStore() = default;
};

#endif //IDEVICETOKENSTORE_H
