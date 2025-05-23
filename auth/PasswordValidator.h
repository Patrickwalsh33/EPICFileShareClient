#ifndef PASSWORDVALIDATOR_H
#define PASSWORDVALIDATOR_H

#include <QString>
#include "CommonPasswordChecker.h"

class PasswordValidator {
public:
    PasswordValidator(CommonPasswordChecker* checker);

    //Nist SP800-63B password validation
    bool validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg);
    bool validateUsername(const QString& username, QString& errorMsg); //function can change error message but cant change username

private:
    CommonPasswordChecker* passwordChecker;
};

#endif //PASSWORDVALIDATOR_H
