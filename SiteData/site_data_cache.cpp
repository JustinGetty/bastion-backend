//
// Created by root on 5/29/25.
//

#include "../Headers/site_data_cache.h"
#include "database_comm_v2.h"

std::shared_mutex site_data_cache::mtx;
std::unordered_map<std::string, site_data_cache_object> site_data_cache::site_data_cache_map;


void site_data_cache::update_cache_flag(std::string *username, bool flag) {
    std::lock_guard<std::shared_mutex> lock(mtx);
    site_data_cache_map[*username].has_update = flag;
}

//true for if it has new data, false if not. This will check if new data needs to be pulled, and if username doesnt exist it will add them to the cache
bool site_data_cache::check_flag_update_and_fetch_site_data(std::string* username, std::vector<site_data_for_mobile>* data_out) {
    std::lock_guard<std::shared_mutex> lock(mtx);

    auto data_temp = site_data_cache_map.find(*username);

    if (data_temp != site_data_cache_map.end() && data_temp->second.has_update == false && !data_temp->second.site_data.empty()) {
        *data_out = data_temp->second.site_data;
        return false;
    }

    std::vector<site_data_for_mobile> fresh_data;
    STATUS status = get_site_data_for_mobile(username, &fresh_data);
    if (status == SUCCESS) {
        *data_out = fresh_data;

        auto& entry = site_data_cache_map[*username];
        entry.site_data = std::move(fresh_data);
        entry.has_update = false;

        return true;
    }

    data_out->clear();
    return false;
}


void site_data_cache::remove_user_from_site_data_cache(std::string *username) {
    std::lock_guard<std::shared_mutex> lock(mtx);
    site_data_cache_map.erase(*username);
}
