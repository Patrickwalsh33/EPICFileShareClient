#pragma once

#include <QString>
#include "validation.h"
#include "../key_management/MasterKeyDerivation.h"
#include "../key_management/EncryptionKeyGenerator.h"
#include "../key_management/KEKManager.h"

extern std::vector<unsigned char> masterKeySalt;
extern std::vector<unsigned char> encryptedKEK;
extern std::vector<unsigned char> kekNonce;

class UserAuthentication {

public:

    UserAuthentication(PasswordValidator* validator);
    ~UserAuthentication();
    
    // Register a new user
    bool registerUser(const QString& username, const QString&  qpassword, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);

    bool changePassword(const std::string& oldPassword, const std::string& newPassword, std::vector<unsigned char>& salt, std::vector<unsigned char>& en_kek, std::vector<unsigned char>& nonce);

private:
    PasswordValidator* validator;
    MasterKeyDerivation* masterKeyDerivation;
    EncryptionKeyGenerator* encryptionKeyGenerator;
    KEKManager* kekManager;

    std::string deriveMasterKeyFromPassword(const QString& password, const std::vector<unsigned char>& salt);
    // TODO: Add database connection or storage mechanism
};
