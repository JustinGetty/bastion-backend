//
// Created by root on 5/19/25.
//

#ifndef DBSERVICE_H
#define DBSERVICE_H
#include "Scheduler.h"
#include "UserDAO.h"
#include "Future.h"
#include "DatabaseRequest.h"
#include "DAO.h"

class DBService {
    Scheduler& sched;
    UserDAO    userDao;
public:
    explicit DBService(Scheduler& s, sqlite3* db);
    Future<User> getUserById(int id);
};

#endif //DBSERVICE_H
