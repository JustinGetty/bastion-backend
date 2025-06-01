//
// Created by root on 6/1/25.
//

#ifndef ISITEWRITER_H
#define ISITEWRITER_H

struct ISiteWriter {
    virtual void insertRequest(const int site_id, const std::string username, const int approved) = 0;
    virtual ~ISiteWriter() = default;
};

#endif //ISITEWRITER_H
