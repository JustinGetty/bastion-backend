//
// Created by root on 5/19/25.
//

#ifndef IDATABASEREQUEST_H
#define IDATABASEREQUEST_H

struct IDatabaseRequest {
    //abstract in "java" terms lol
    virtual void execute() = 0;
    virtual ~IDatabaseRequest() = default;
};

#endif
