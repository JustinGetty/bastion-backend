//
// Created by root on 5/19/25.
//

#ifndef DAO_H
#define DAO_H

template<typename T>
struct DAO {
    virtual T get_user_by_uname(std::string) = 0;
    virtual ~DAO() = default;
};

#endif //DAO_H
