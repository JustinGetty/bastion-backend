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
    std::ostringstream body_text;
    body_text << "This is an email from: " << username << "enjoy!\n";
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
STATUS validate_verification_codes(std::string rec_verif_code) {
    //create helper, compare codes, return, etc.

    return SUCCESS;
}

bool EmailSys::get_verification_status() {
    return is_verified;
}
