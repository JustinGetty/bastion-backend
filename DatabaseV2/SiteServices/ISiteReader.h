//
// Created by root on 6/1/25.
//

#ifndef ISITEREADER_H
#define ISITEREADER_H
#include <iostream>

struct ISiteReader {
    virtual int getClientIdBySpaId(const std::string spa_id) = 0;
    virtual ~ISiteReader() = default;
};

#endif //ISITEREADER_H
