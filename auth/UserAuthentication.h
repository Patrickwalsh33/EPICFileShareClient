#ifndef USERAUTHENTICATION_H
#define USERAUTHENTICATION_H

#include <QString>
#include "PasswordValidator.h"

class UserAuthentication {
public:
    UserAuthentication(PasswordValidator* validator);
    
    // Register a new user
    bool registerUser(const QString& username, const QString& password, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);

private:
    PasswordValidator* validator;
    
    // TODO: Add database connection or storage mechanism
};

#endif // USERAUTHENTICATION_H
