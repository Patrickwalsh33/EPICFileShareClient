#ifndef USERAUTHENTICATION_H
#define USERAUTHENTICATION_H

#include <QString>
#include "validation.h"
#include "../key_management/MasterKeyDerivation.h"
#include "../key_management/EncryptionKeyGenerator.h"
#include "../key_management/KEKManager.h"

class UserAuthentication {
public:
    UserAuthentication(PasswordValidator* validator);
    ~UserAuthentication();
    
    // Register a new user
    bool registerUser(const QString& username, const QString&  qpassword, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);

private:
    PasswordValidator* validator;
    MasterKeyDerivation* masterKeyDerivation;
    EncryptionKeyGenerator* encryptionKeyGenerator;
    KEKManager* kekManager;

    std::string deriveMasterKeyFromPassword(const QString& password, const std::vector<unsigned char>& salt);
    // TODO: Add database connection or storage mechanism
};

#endif // USERAUTHENTICATION_H
