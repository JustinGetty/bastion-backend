//
// Created by root on 5/19/25.
//

#ifndef FUTURE_H
#define FUTURE_H
#include <future>
template<typename T>
class Future {
    //returns type T
    std::future<T> fut;
public:
    explicit Future(std::future<T> fut_)
        : fut(std::move(fut_)){}
        //create generic override for future.get() return type - whether it's User or ID or whatever
        T get() {
            return fut.get();
        }
        //generic override for valid
        bool valid() const noexcept {
        return fut.valid();
    }
};

template<>
class Future<void> {
    std::future<void> fut;
public:
    explicit Future(std::future<void> f)
      : fut(std::move(f))
    {}

    //blocks until ready, returns nothing
    void get() {
        fut.get();
    }

    bool valid() const noexcept {
        return fut.valid();
    }
};

#endif //FUTURE_H
