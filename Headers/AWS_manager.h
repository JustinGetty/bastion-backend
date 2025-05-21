//
// Created by root on 5/21/25.
//

#ifndef AWS_MANAGER_H
#define AWS_MANAGER_H

#include <aws/core/Aws.h>
#include <aws/sesv2/SESV2Client.h>
#include <aws/lambda/LambdaClient.h>

class AWS_manager {
public:
    static AWS_manager& Instance();
    Aws::SESV2::SESV2Client& get_ses_client();
    Aws::Lambda::LambdaClient& get_lambda_client();
private:
    AWS_manager();
    ~AWS_manager();

    //block copying for redundancy
    AWS_manager(const AWS_manager&)            = delete;
    AWS_manager& operator=(const AWS_manager&) = delete;
    //this takes in the access_key and secret_key
    Aws::SDKOptions options_;
    std::unique_ptr<Aws::SESV2::SESV2Client>   sesClient_;
    std::unique_ptr<Aws::Lambda::LambdaClient> lambdaClient_;

};



#endif //AWS_MANAGER_H
