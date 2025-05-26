#ifndef VALIDATION_H
#define VALIDATION_H

#include <QString>
#include <QRegularExpression>
#include "CommonPasswordChecker.h"

class InputSanitizer {
public:
    // Username sanitization
    static bool sanitizeUsername(QString& username, QString& errorMsg);
    
    // Password sanitization
    static bool sanitizePassword(QString& password, QString& errorMsg);

private:
    // Maximum input lengths
    static const int maxUsernameLength = 50;
    static const int minUsernameLength = 6;
    static const int maxPasswordLength = 128;
    static const int minPasswordLength = 8;

    static bool validateInputLength(const QString& input, int minLength, int maxLength, QString& errorMsg);
    static bool containsDangerousPatterns(const QString& input);
};

class PasswordValidator {
public:
    PasswordValidator(CommonPasswordChecker* checker);
    
    bool validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg);
    bool validateUsername(const QString& username, QString& errorMsg);

private:
    CommonPasswordChecker* passwordChecker;
};

#endif // VALIDATION_H 