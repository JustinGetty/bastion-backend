//
// Created by root on 5/19/25.
//

#ifndef DATABASEREQUEST_H
#define DATABASEREQUEST_H
#include <algorithm>
#include <exception>

#include "Future.h"
#include "IDatabaseRequest.h"
#include "Promise.h"
#include <future>

template<typename T>
class DatabaseRequest : public IDatabaseRequest {
    //pass this class a function to execute and the promise to give the value to, it will then
    //generically execute and set the value
    std::function<T()> exec_function;
    Promise<T> promise;
public:
    explicit DatabaseRequest(std::function<T()>&& function_in)
        : exec_function(std::move(function_in)), promise() {}

    void execute() override {
        try {
            T result = exec_function();
            promise.setValue(result);
        } catch (...) {
            promise.setException(std::current_exception());
        }
    }

    Future<T> getFuture() {
        return promise.getFuture();
    }

};

template<>
class DatabaseRequest<void> : public IDatabaseRequest {
    std::function<void()> exec_function;
    Promise<void>         promise;
public:
    explicit DatabaseRequest(std::function<void()>&& fn)
      : exec_function(std::move(fn)), promise()
    {}

    void execute() override {
        try {
            exec_function();
            promise.setValue();
        } catch (...) {
            promise.setException(std::current_exception());
        }
    }

    Future<void> getFuture() {
        return promise.getFuture();
    }
};

#endif //DATABASEREQUEST_H
