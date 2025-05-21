//
// Created by root on 5/21/25.
//

#include "AWS_manager.h"
#include <aws/core/Aws.h>
#include <aws/sesv2/SESV2Client.h>
#include <aws/lambda/LambdaClient.h>

AWS_manager::AWS_manager() {
    Aws::InitAPI(options_);
    Aws::Client::ClientConfiguration clientConfiguration;
    clientConfiguration.region = "us-east-1";
    sesClient_ = std::make_unique<Aws::SESV2::SESV2Client>(clientConfiguration);
    lambdaClient_ = std::make_unique<Aws::Lambda::LambdaClient>(clientConfiguration);
}

AWS_manager::~AWS_manager() {
    Aws::ShutdownAPI(options_);
}

AWS_manager& AWS_manager::Instance() {
    static AWS_manager inst_manager;
    return inst_manager;
}

Aws::SESV2::SESV2Client& AWS_manager::get_ses_client() {
   return *sesClient_;
}
Aws::Lambda::LambdaClient& AWS_manager::get_lambda_client() {
    return *lambdaClient_;
}
