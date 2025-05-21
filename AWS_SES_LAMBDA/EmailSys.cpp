//
// Created by root on 5/21/25.
//

#include "../Headers/EmailSys.h"
#include <iostream>
#include "AWS_manager.h"
#include <ostream>
#include <aws/core/Aws.h>
#include <aws/sesv2/SESV2Client.h>
#include <aws/sesv2/model/SendEmailRequest.h>
#include <aws/sesv2/model/Destination.h>
#include <aws/sesv2/model/EmailContent.h>
#include <aws/sesv2/model/Body.h>
#include <aws/sesv2/model/Content.h>
#include <cstdlib>

std::string EmailSys::generate_verification_code() {
    std::srand(static_cast<unsigned>(std::time(nullptr)));
    int code = std::rand() % 900000 + 100000;
    std::string str_code = std::to_string(code);
    std::cout << "[INFO] Verification code generated: " << str_code << "\n";

    verification_code = str_code;

    return str_code;
}

EmailSys::EmailSys(const std::string* username, const std::string *email) : username(*username), user_email(*email){
    is_verified = false;
};

STATUS EmailSys::send_email_for_verification() {

    Aws::SESV2::Model::Destination dest;
    dest.AddToAddresses(user_email);

    //subject
    Aws::SESV2::Model::Content subj;
    subj.SetData("New Verification Request From BastionAuth");
    subj.SetCharset("UTF-8");

    //body text
    Aws::SESV2::Model::Content textBody;

    std::string verification_code = generate_verification_code();

    std::ostringstream body_text;
    body_text << "This is an email to verify new user: " << username << ".\nYour Verification code is: " << verification_code;
    textBody.SetData(body_text.str());
    textBody.SetCharset("UTF-8");

    Aws::SESV2::Model::Body body;
    body.SetText(textBody);

    //message sub + body
    Aws::SESV2::Model::Message msgDef;
    msgDef.SetSubject(subj);
    msgDef.SetBody(body);

    //wrap in .simple
    Aws::SESV2::Model::EmailContent emailContent;
    emailContent.SetSimple(msgDef);

    //send
    Aws::SESV2::Model::SendEmailRequest email_req;
    email_req.SetFromEmailAddress("noreply@bastionauth.com");
    email_req.SetDestination(dest);
    email_req.SetContent(emailContent);


    auto outcome  = AWS_manager::Instance().get_ses_client().SendEmail(email_req);
    if (!outcome.IsSuccess()) {
        std::cerr << "[ERROR] SES Error sending email to: " << username << "\n" << "    Error Message: " << outcome.GetError().GetMessage() << "\n";
        return EMAIL_SEND_FAILURE;
    } else {
        std::cout << "[INFO] Email sent successfully for user: " << username << "\n";
        return SUCCESS;
    }

}
STATUS EmailSys::validate_verification_codes(const std::string rec_verif_code) {
    //create helper, compare codes, return, etc.
    if (!rec_verif_code.empty() && rec_verif_code == verification_code) {
        is_verified = true;
        return SUCCESS;
    }
    is_verified = false;
    return CODE_VERIFICATION_FAILURE;
}

bool EmailSys::get_verification_status() {
    return is_verified;
}

std::string EmailSys::get_verification_code() {
    return verification_code;
}
