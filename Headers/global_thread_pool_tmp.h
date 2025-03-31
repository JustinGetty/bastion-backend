//
// Created by root on 3/31/25.
//

#ifndef GLOBAL_THREAD_POOL_TMP_H
#define GLOBAL_THREAD_POOL_TMP_H
#include "../Headers/thread_pool.h"
#include "../Validation/validation_work.h"

//THIS IS FOR VALIDATION WORK

extern CircularQueue<validation_work*> g_workQueue;

#endif //GLOBAL_THREAD_POOL_TMP_H
