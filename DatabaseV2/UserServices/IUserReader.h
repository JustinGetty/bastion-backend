//
// Created by root on 5/20/25.
//

#ifndef IUSERREADER_H
#define IUSERREADER_H
#include <bastion_data.h>

struct IUserReader {
    virtual full_user_data findById(int id) = 0;
    virtual full_user_data findByUsername(const std::string& uname) = 0;
    virtual bool getUserSiteDataExists(const std::string username) = 0;
    virtual bool getUsernameExists(const std::string username) = 0;
    virtual std::vector<site_data_for_mobile> getSiteDataForMobileUser(std::string username) = 0;

    using seed_phrase_hash = std::array<unsigned char, 32>;
    virtual seed_phrase_hash getSeedPhraseHash(const std::string username) = 0;

    using token_sec = std::array<unsigned char, 64>;
    virtual token_sec getSymEncAuthToken(const std::string username) = 0;
    virtual std::string getDeviceToken(const std::string username) = 0;

    virtual ~IUserReader() = default;
};

#endif //IUSERREADER_H
