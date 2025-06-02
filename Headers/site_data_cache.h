//
// Created by root on 5/29/25.
//

#ifndef SITE_DATA_CACHE_H
#define SITE_DATA_CACHE_H
#include <bastion_data.h>
#include <mutex>
#include <shared_mutex>


class site_data_cache {

public:
    static void update_cache_flag(std::string *username, bool flag);
    //true for if it has new data, false if not. This will check if new data needs to be pulled, and if username doesnt exist it will add them to the cache
    static bool check_flag_update_and_fetch_site_data(std::string *username, std::vector<site_data_for_mobile> *data_out);
    static void remove_user_from_site_data_cache(std::string *username);

private:
    static std::shared_mutex mtx;
    //TODO this shit needs to eventually go on the heap and hold pointers not values
    static std::unordered_map<std::string, site_data_cache_object> site_data_cache_map;
};



#endif //SITE_DATA_CACHE_H
