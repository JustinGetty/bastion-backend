//
// Created by root on 5/19/25.
//

#include "../Headers/database_comm_v2.h"
#include "Scheduler.h"
#include "DBService.h"
#include <sqlite3.h>
#include <iostream>
#include <bastion_data.h>

#include "EmailDAO.h"

sqlite3*   g_db        = nullptr;
Scheduler  g_sched;
DBService* g_dbService = nullptr;


STATUS start_db_comm() {
    if (sqlite3_open_v2(DATABASE, &g_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        return UNKNOWN_FAILURE;
    }
    sqlite3_exec(g_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    //sqlite3_busy_timeout(g_db, 5000);

    //start the thread pool
    g_sched.start(10);

    //construct the one DBService
    //    note: DBService has no default ctor, so use new
    auto userReader = std::make_unique<UserDAO>(g_db);
    auto userWriter = std::make_unique<UserDAO>(g_db);
    auto deviceStore = std::make_unique<DeviceDAO>(g_db);
    auto emailStore = std::make_unique<EmailDAO>(g_db);

    //move into DBService
    g_dbService = new DBService(
        g_sched,
        std::move(userReader),
        std::move(userWriter),
        std::move(deviceStore),
        std::move(emailStore)
    );
    return SUCCESS;
}

void shutdown_db_comm() {
    g_sched.shutdown();

    delete g_dbService;
    g_dbService = nullptr;

    sqlite3_close(g_db);
    g_db = nullptr;
}

STATUS get_user_by_username_v2(bastion_username *uname, full_user_data *user_data) {
    std::string username = *uname;
    auto future_ = g_dbService->getUserByName(username);
    *user_data = future_.get();
    return SUCCESS;
}

STATUS insert_ios_device_token_by_username_v2(bastion_username *uname, ios_device_token *device_token) {
    auto future_ = g_dbService->storeDeviceToken(*uname, *device_token);
    future_.get();

    return SUCCESS;
}

STATUS insert_user_email_by_username(std::string uname, std::string email, std::string email_hash, std::string client_spa_id) {
    auto future_ = g_dbService->storeUserEmail(uname, email, email_hash, client_spa_id);
    future_.get();
    return SUCCESS;
}

//out = false means they do not exist, true if they do
STATUS check_if_user_is_new_to_site(const std::string username, bool *out) {
    auto future_ = g_dbService->checkUserSite(username);
    *out = future_.get();
    return SUCCESS;
}
STATUS get_site_data_for_mobile(const std::string* username, std::vector<site_data_for_mobile>* site_data_out) {
    auto future_ = g_dbService->getSiteDataForMobile(*username);
    *site_data_out = future_.get();
    return SUCCESS;
}

STATUS update_site_usage_count(const std::string *spa_id) {
    auto future_ = g_dbService->updateSiteUsageCount(*spa_id);
    future_.get();
    return SUCCESS;
}


STATUS update_user_site_last_usage(const std::string * username, const std::string *spa_id) {
    auto future_ = g_dbService->updateUserLastUsedTime(*username, *spa_id);
    future_.get();
    return SUCCESS;
}
