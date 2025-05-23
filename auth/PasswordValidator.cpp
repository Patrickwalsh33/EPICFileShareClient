#include "PasswordValidator.h"

PasswordValidator::PasswordValidator(CommonPasswordChecker* checker)
    : passwordChecker(checker) {
}

bool PasswordValidator::validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg){
    
    //First check if the passwords match
    if (password!= confirmPassword){
        errorMsg= "Passwords dont match";
        return false;
    } 

    // Check the minimum length
    if (password.length() < 8){
        errorMsg = "Password must be at least 8 characters long";
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

bool PasswordValidator::validateUsername(const QString& username, QString& errorMsg)
{
    if (username.isEmpty()) {
        errorMsg = "Username cannot be empty";
        return false;
    }
    
    if (username.length() < 6) {
        errorMsg = "Username must be at least 6 characters long";
        return false;
    }
    
    // Check for spaces
    if (username.contains(' ')) {
        errorMsg = "Username cannot contain spaces";
        return false;
    }
    
    return true;
}
