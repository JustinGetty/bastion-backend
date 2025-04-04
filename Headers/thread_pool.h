#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include <thread>
#include <vector>
#include <atomic>
#include <chrono>
#include "circular_queue.h"
#include "validation_work.h"

class ThreadPool {
public:
    ThreadPool(size_t num_threads, CircularQueue<validation_work*>& queue)
        : queue_(queue), stopped(false)
    {
        for (size_t i = 0; i < num_threads; ++i) {
            threads_.emplace_back([this]() {
                while (!stopped.load()) {
                    validation_work* work = nullptr;
                    if (queue_.try_pop(work)) {
                        if (work != nullptr) {
                            work->execute();
                            delete work;
                        }
                    } else {
                        std::this_thread::sleep_for(std::chrono::milliseconds(10));
                    }
                }
            });
        }
    }

    ~ThreadPool() {
        stop();
    }

    // Signal the thread pool to stop and join all threads.
    void stop() {
        stopped.store(true);
        for (std::thread& t : threads_) {
            if (t.joinable()) {
                t.join();
            }
        }
    }

private:
    CircularQueue<validation_work*>& queue_;
    std::vector<std::thread> threads_;
    std::atomic<bool> stopped;
};

#endif // THREAD_POOL_H
