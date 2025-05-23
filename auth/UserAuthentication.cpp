#include "UserAuthentication.h"
#include <QDebug>

UserAuthentication::UserAuthentication(PasswordValidator* validator)
    : validator(validator) {
}

bool UserAuthentication::registerUser(const QString& username, const QString& password, const QString& confirmPassword, QString& errorMsg) {
    // Validate username
    if (!validator->validateUsername(username, errorMsg)) {
        return false;
    }
    
    // Validate password
    if (!validator->validatePassword(password, confirmPassword, errorMsg)) {
        return false;
    }
    
    
    qDebug() << "User registration successful for:" << username;
    
    return true;
}

bool UserAuthentication::loginUser(const QString& username, const QString& password, QString& errorMsg) {
   
    
    // For now, return success if username and password are not empty
    if (username.isEmpty() || password.isEmpty()) {
        errorMsg = "Username and password cannot be empty";
        return false;
    }
    
    qDebug() << "Login attempt for user:" << username;
    
    // TODO: Check credentials against database
    
    return true;
}
