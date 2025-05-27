#include "validation.h"
#include <QDebug>

// InputSanitizer implementation
bool InputSanitizer::validateInputLength(const QString& input, int minLength, int maxLength, QString& errorMsg){
    if(input.length() < minLength){
        errorMsg = "Input is too short";
        return false;
    }

    if (input.length() > maxLength) {
        errorMsg = "Input is too long";
        return false;
    }

    return true;
}

bool InputSanitizer::containsDangerousPatterns(const QString& input){
    //common attack patterns
    QStringList dangerousPatterns = {
        "../", "..\\",           // Path traversal
        "SELECT", "INSERT", "DROP", "DELETE",  // SQL injection
        "<script", "javascript:", "onload=",   // XSS
        "'", "\"", ";", "--"     // SQL injection characters
    
    };

    QString upperInput = input.toUpper();
    QString lowerInput = input.toLower();

    for (const QString pattern : dangerousPatterns){
        if (upperInput.contains(pattern.toUpper()) || lowerInput.contains(pattern.toLower())){
            qDebug() << "Dangerous pattern inputed" << pattern << "in: " << input;
            return true;
        }
    }
    return false;
}

bool InputSanitizer::sanitizeUsername(QString& username, QString& errorMsg){

    username = username.trimmed(); // this removes whitespace

    if (username.isEmpty()){
        errorMsg = "Username cannot be empty";
        return false;
    }

//check length limits
    if(!validateInputLength(username, minUsernameLength, maxUsernameLength, errorMsg)){
        return false;
    }

    //check for dangerous patterns
    if (containsDangerousPatterns(username)){
        errorMsg = "Username contains invalid characters";
        return false;
    }

    //This makes it only allow to use alpabetic , numbers ,underscores and hyphens
    //stops sql injection

    QRegularExpression validUsernameRegex("^[a-zA-Z0-9_-]+$");
    if(!validUsernameRegex.match(username).hasMatch()){
        errorMsg = "Username can only contain letters, numbers, underscores, and hyphens";
        return false;
    }

    QStringList reservedNames = {"admin", "test", "null"};
    if (reservedNames.contains(username.toLower())){
        errorMsg = "Username is reserved";
        return false;
    }

    return true;
}

//for passwords we want to have less sanitation to perserve security
// i.e if malory finds source code and sees that password cant contain 
// special characters its a security risk
bool InputSanitizer::sanitizePassword(QString& password, QString& errorMsg){

    if(password.isEmpty()){
        errorMsg = "Password cannot be empty";
        return false;
    }

    if (!validateInputLength(password, minPasswordLength, maxPasswordLength, errorMsg)){
        return false;
    }

    //check for null bytes
    if (password.contains('\0')){
        errorMsg = "Password contains invalid character";
        return false;
    }

    return true;
}

// PasswordValidator implementation
PasswordValidator::PasswordValidator(CommonPasswordChecker* checker)
    : passwordChecker(checker) {
}

bool PasswordValidator::validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg){
    
    //First check if the passwords match
    if (password!= confirmPassword){
        errorMsg= "Passwords dont match";
        return false;
    } 

    // Use InputSanitizer for security validation
    QString tempPassword = password;
    if (!InputSanitizer::sanitizePassword(tempPassword, errorMsg)) {
        return false;
    }

    if (passwordChecker->isCommonPassword(password)){
        errorMsg = "This password is too commonly used ";
        return false;
    }

    bool hasRepeats = false;
    for (int i = 0; i < password.length() - 2; i++){
        if (password[i] == password[i + 1] && password[i] == password[i+2]){
            hasRepeats = true;
            break;
        }
    }

    if (hasRepeats){
        errorMsg = "password contains too many repeated characters";
        return false;
    }
    
    return true;
}

bool PasswordValidator::validateUsername(const QString& username, QString& errorMsg){
    // Use InputSanitizer for security validation
    QString tempUsername = username;
    return InputSanitizer::sanitizeUsername(tempUsername, errorMsg);
}
