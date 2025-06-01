//
// Created by root on 5/28/25.
//

#ifndef APIHANDLERBOOSTPOOL_H
#define APIHANDLERBOOSTPOOL_H

#include <vector>
#include <memory>
#include <thread>
#include <queue>
#include <functional>
#include <condition_variable>


class apiHandlerBoostPool {
public:
    explicit apiHandlerBoostPool(size_t num_threads);
    ~apiHandlerBoostPool();
    apiHandlerBoostPool(const apiHandlerBoostPool&) = delete;
    apiHandlerBoostPool& operator=(const apiHandlerBoostPool&) = delete;

    template<class F>
    void enqueue(F&& f) {
        {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stop_)
            throw std::runtime_error("enqueue on stopped ThreadPool");
        tasks_.emplace(std::forward<F>(f));
        }
        cond_.notify_one();
    }

private:
    std::vector<std::thread>            workers_;
    std::queue<std::function<void()>>   tasks_;
    std::mutex                          mutex_;
    std::condition_variable             cond_;
    bool                                stop_;

};



#endif //APIHANDLERBOOSTPOOL_H
