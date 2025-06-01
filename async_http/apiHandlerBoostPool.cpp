//
// Created by root on 5/28/25.
//

#include "../Headers/apiHandlerBoostPool.h"

apiHandlerBoostPool::apiHandlerBoostPool(size_t num_threads) : stop_(false) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(this->mutex_);
                    this->cond_.wait(lock, [this] {
                        return this->stop_ || !this->tasks_.empty();
                    });
                    //shutdown if stopping and no tasks remain!!!!
                    if (this->stop_ && this->tasks_.empty())
                        return;
                    task = std::move(this->tasks_.front());
                    this->tasks_.pop();
                }
                task(); //run lambda
            }
        });
    }
}
apiHandlerBoostPool::~apiHandlerBoostPool() {
    {
    std::unique_lock<std::mutex> lock(mutex_);
    stop_ = true;
    }

    cond_.notify_all();
    for (std::thread &t : workers_)
        t.join();

}

