//
// Created by root on 5/19/25.
//

#include "DBService.h"
#include "User.h"

DBService::DBService(Scheduler& s, sqlite3* db)
  : sched(s), userDao(db)
{}


Future<full_user_data> DBService::getUserDataByUsername(std::string username) {
    auto work = [this, username](){ return userDao.get_user_by_uname(username); };
    auto req  = std::make_unique<DatabaseRequest<full_user_data>>(std::move(work));
    Future<full_user_data> fut = req->getFuture();
    sched.enqueue(std::move(req));
    return fut;
}
