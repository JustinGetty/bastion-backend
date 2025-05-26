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
#include <format>


static constexpr auto verificationEmailHtml = R"HTML(
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bastion Auth - Verification Code</title>
    </head>
    <body style="margin: 0; padding: 0; box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; line-height: 1.6; color: #333; background-color: #f8fafc;">
        <div style="max-width: 600px; margin: 40px auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); overflow: hidden;">
            <div style="background: #4338ca; padding: 32px 24px; text-align: center; position: relative;">


            <div style="position: relative; z-index: 1; color: #ffffff; font-size: 28px; font-weight: 700; margin-bottom: 8px; text-align: center;">
                Bastion Auth
            </div>

                <div style="position: relative; z-index: 1; color: #94a3b8; font-size: 14px; font-weight: 500; letter-spacing: 0.5px;">SECURE • RELIABLE • TRUSTED</div>
            </div>

            <div style="padding: 40px 32px;">
                <div style="font-size: 18px; font-weight: 600; color: #1e293b; margin-bottom: 16px;">Hello, {}</div>

                <div style="color: #64748b; font-size: 16px; margin-bottom: 32px; line-height: 1.7;">
                    You've requested a verification code to secure your account. Use the code below to complete your authentication process.
                </div>

                <div style="background: linear-gradient(135deg, #f1f5f9 0%, #e2e8f0 100%); border: 2px solid #e2e8f0; border-radius: 12px; padding: 32px 24px; text-align: center; margin: 32px 0; position: relative; overflow: hidden;">
                    <div style="position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(67, 56, 202, 0.08) 0%, transparent 70%);"></div>

                    <div style="font-size: 14px; font-weight: 600; color: #475569; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; position: relative; z-index: 1;">Your Verification Code</div>
                    <div style="font-size: 36px; font-weight: 800; color: #1e293b; font-family: 'Courier New', monospace; letter-spacing: 8px; background: #ffffff; padding: 16px 24px; border-radius: 8px; border: 2px solid #4338ca; display: inline-block; box-shadow: 0 4px 12px rgba(67, 56, 202, 0.2); position: relative; z-index: 1;">{}</div>
                </div>

                <div style="background: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px 20px; margin: 32px 0; border-radius: 0 8px 8px 0;">
                    <div style="font-weight: 600; color: #92400e; margin-bottom: 8px; font-size: 14px;">🔒 Security Notice</div>
                    <div style="color: #a16207; font-size: 14px; line-height: 1.6;">
                        This code expires in 10 minutes and can only be used once. Never share this code with anyone. If you didn't request this code, please contact our security team immediately.
                    </div>
                </div>

                <div style="color: #64748b; font-size: 16px; line-height: 1.7;">
                    If you're having trouble with verification, our support team is here to help 24/7.
                </div>
            </div>

            <div style="background: #f8fafc; padding: 24px 32px; border-top: 1px solid #e2e8f0; text-align: center;">
                <div style="color: #64748b; font-size: 14px; margin-bottom: 8px;">
                    This is an automated security message from Bastion Auth.
                </div>
                <div style="color: #94a3b8; font-size: 12px;">
                    © 2025 Bastion Auth. All rights reserved.
                </div>
            </div>
        </div>
    </body>
    </html>
    )HTML";

std::string makeEmailBody(const std::string& user, const std::string& code) {
    return std::format(verificationEmailHtml, user, code);
}

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

    std::string body_text_finalized = makeEmailBody(username, verification_code);

    Aws::SESV2::Model::Content htmlPart;
    htmlPart.SetData(body_text_finalized);
    htmlPart.SetCharset("UTF-8");

    Aws::SESV2::Model::Content textPart;
    textPart.SetData(
        "Your BastionAuth verification code is: " + verification_code +
        "\n\nIf you can't see this email properly, please use an HTML-capable client."
    );
    textPart.SetCharset("UTF-8");

    // multipart/alternative body
    Aws::SESV2::Model::Body body;
    body.SetHtml(htmlPart);
    body.SetText(textPart);

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
