//
// Created by root on 5/19/25.
//

#include "DBService.h"
#include "User.h"

DBService::DBService(Scheduler& s, sqlite3* db)
  : sched(s), userDao(db)
{}

Future<User> DBService::getUserById(int id) {
    auto work = [this, id](){ return userDao.findById(id); };
    auto req  = std::make_unique<DatabaseRequest<User>>(std::move(work));
    Future<User> fut = req->getFuture();
    sched.enqueue(std::move(req));
    return fut;
}