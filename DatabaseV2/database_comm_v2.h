//
// Created by root on 5/19/25.
//

#ifndef DATABASE_COMM_V2_H
#define DATABASE_COMM_V2_H
#include <bastion_data.h>
#include "sqlite3.h"
#include "Scheduler.h"
#include "DBService.h"

extern sqlite3*    g_db;
extern Scheduler   g_sched;
extern DBService*  g_dbService;

STATUS start_db_comm();
void shutdown_db_comm();
STATUS get_user_by_username_v2(bastion_username *uname, full_user_data *user_data);

#endif //DATABASE_COMM_V2_H
