//
// Created by root on 5/20/25.
//

#ifndef IUSERREADER_H
#define IUSERREADER_H
#include <bastion_data.h>

struct IUserReader {
    virtual full_user_data findById(int id) = 0;
    virtual full_user_data findByUsername(const std::string& uname) = 0;
    virtual bool getUserSiteDataExists(const std::string username) = 0;
    virtual std::vector<site_data_for_mobile> getSiteDataForMobileUser(std::string username) = 0;
    virtual ~IUserReader() = default;
};

#endif //IUSERREADER_H
