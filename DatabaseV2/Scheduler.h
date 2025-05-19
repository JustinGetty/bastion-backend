//
// Created by root on 5/19/25.
//

#ifndef SCHEDULER_H
#define SCHEDULER_H

#include <condition_variable>
#include <deque>

#include "IDatabaseRequest.h"
#include <vector>


class Scheduler {
    std::mutex mtx;
    std::condition_variable cv;
    //deque = double ended queue, vector but with efficient add/remove at front
    std::deque<std::unique_ptr<IDatabaseRequest>> queue;
    std::vector<std::thread> thread_pool;
    bool running = false;

public:
    void start(size_t thread_num);
    void enqueue(std::unique_ptr<IDatabaseRequest> request);
    void shutdown();
};



#endif //SCHEDULER_H
