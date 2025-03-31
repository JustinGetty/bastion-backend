//
// Created by root on 3/28/25.
//

#ifndef VALIDATION_WORK_H
#define VALIDATION_WORK_H


void setup_work_threads();

class validation_work {
public:
    virtual ~validation_work() {}
    virtual void execute() = 0;



};








#endif //VALIDATION_WORK_H
