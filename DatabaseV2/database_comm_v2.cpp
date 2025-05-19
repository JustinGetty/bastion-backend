//
// Created by root on 5/19/25.
//

#include "database_comm_v2.h"
#include "Scheduler.h"
#include "DBService.h"
#include "User.h"
#include <sqlite3.h>
#include <iostream>
#include <bastion_data.h>

sqlite3*   g_db        = nullptr;
Scheduler  g_sched;
DBService* g_dbService = nullptr;

int get_id() {

}

STATUS start_db_comm() {
    if (sqlite3_open(DATABASE, &g_db) != SQLITE_OK) {
        return UNKNOWN_FAILURE;
    }

    // 3) start the thread pool
    g_sched.start(10);

    // 4) construct the one DBService
    //    note: DBService has no default ctor, so we use new
    g_dbService = new DBService(g_sched, g_db);

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
    auto future_ = g_dbService->getUserDataByUsername(username);
    *user_data = future_.get();
    return SUCCESS;
}


