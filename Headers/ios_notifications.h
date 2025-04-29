//
// Created by root on 4/27/25.
//

#ifndef IOS_NOTIFICATIONS_H
#define IOS_NOTIFICATIONS_H

#include <iostream>
#include <bastion_data.h>

STATUS notify_signin_request(const std::string& username,
                           const std::string& siteName,
                           const std::string& siteUrl,
                           const std::string& requestId);
#endif //IOS_NOTIFICATIONS_H
