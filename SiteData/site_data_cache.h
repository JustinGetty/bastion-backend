//
// Created by root on 5/29/25.
//

#ifndef SITE_DATA_CACHE_H
#define SITE_DATA_CACHE_H
#include <bastion_data.h>
#include <mutex>


class site_data_cache {

public:
    site_data_cache();
    ~site_data_cache();
    void update_cache_flag(std::string *username, bool flag);

private:
    std::mutex mtx;
    std::unordered_map<std::string, site_data_cache_object> site_data_cache_map;
};



#endif //SITE_DATA_CACHE_H
