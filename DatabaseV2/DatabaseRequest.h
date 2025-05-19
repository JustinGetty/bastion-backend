//
// Created by root on 5/19/25.
//

#ifndef DATABASEREQUEST_H
#define DATABASEREQUEST_H
#include <algorithm>
#include <exception>

#include "Future.h"
#include "IDatabaseRequest.h"

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
            promise.set_value(result);
        } catch (...) {
            promise.set_exception(std::current_exception());
        }
    }
    Future<T> get_future() {
        return promise.get_future();
    }

};

#endif //DATABASEREQUEST_H
