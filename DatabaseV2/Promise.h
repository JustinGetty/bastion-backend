//
// Created by root on 5/19/25.
//

#ifndef PROMISE_H
#define PROMISE_H
#include <algorithm>
#include <exception>

#include "Future.h"

template<typename T>
class Promise {
    std::promise<T> prom;
public:
    Future<T> getFuture() {
        return Future<T>(prom.get_future());
    }
    void setValue(T value) {
        prom.set_value(std::move(value));
    }
    void setException(std::exception_ptr ex) {
        prom.set_exception(ex);
    }

};

#endif //PROMISE_H
