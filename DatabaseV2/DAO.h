//
// Created by root on 5/19/25.
//

#ifndef DAO_H
#define DAO_H

template<typename T>
struct DAO {
    virtual T findById(int) = 0;
    virtual void save(const T&) = 0;
    virtual ~DAO() = default;
};

#endif //DAO_H
