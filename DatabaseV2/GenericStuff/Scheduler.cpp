//
// Created by root on 5/19/25.
//

#include "Scheduler.h"

#include <boost/asio/detail/mutex.hpp>

void Scheduler::start(size_t thread_num) {
   running = true;
   for (size_t i = 0; i < thread_num; i++) {
      thread_pool.emplace_back([this]() {
         while (true) {
            std::unique_ptr<IDatabaseRequest> task;
            {
               std::unique_lock lock(mtx);
               //[&] avoid copies, pass actual values into lambda
               cv.wait(lock, [&] {
                  return !queue.empty() || !running;
               });
               if (!running && queue.empty()) {
                  break;
               }
               task = std::move(queue.front());
               queue.pop_front();
            }
            task->execute();
         }
      });
   }
}

void Scheduler::enqueue(std::unique_ptr<IDatabaseRequest> request) {
   {
      std::lock_guard lock(mtx);
      queue.push_back(std::move(request));
   }
   cv.notify_one();
}

void Scheduler::shutdown() {
   {
      std::lock_guard lock(mtx);
      running = false;
   }
   cv.notify_all();
   for (auto& i : thread_pool) {
      if (i.joinable()) i.join();
   }
}

