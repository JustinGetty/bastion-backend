//
// Created by root on 3/31/25.
//

#ifndef IDEK_WHAT_THIS_SHITS_FOR_ANYMORE_H
#define IDEK_WHAT_THIS_SHITS_FOR_ANYMORE_H

#include "thread_pool.h"
#include "global_thread_pool_tmp.h"
//TODO merge this back with validation_work


inline ThreadPool& getGlobalThreadPool() {
    static ThreadPool pool(4, g_workQueue);
    return pool;
}


#endif //IDEK_WHAT_THIS_SHITS_FOR_ANYMORE_H
