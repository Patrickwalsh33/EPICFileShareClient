#pragma once

#include <QString>
#include "validation.h"
#include "../key_management/MasterKeyDerivation.h"
#include "../key_management/EncryptionKeyGenerator.h"
#include "../key_management/KEKManager.h"

class UserAuthentication {
public:
    UserAuthentication(PasswordValidator* validator);
    ~UserAuthentication();
    static constexpr int DEFAULT_ONETIME_KEYS = 10;
    
    // Register a new user
    bool registerUserLocally(const QString& username, const QString&  qpassword, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);

private:
    PasswordValidator* validator;
    MasterKeyDerivation* masterKeyDerivation;
    EncryptionKeyGenerator* encryptionKeyGenerator;
    KEKManager* kekManager;

    std::string deriveMasterKeyFromPassword(const QString& password, const std::vector<unsigned char>& salt);
    bool generateAndRegisterX3DHKeys(const QString& username, const std::vector<unsigned char>& kek, QString& errorMsg);

    // TODO: Add database connection or storage mechanism
};
