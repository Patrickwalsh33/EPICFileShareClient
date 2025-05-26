#include "UserAuthentication.h"
#include <QDebug>
#include <sodium/crypto_aead_chacha20poly1305.h>


UserAuthentication::UserAuthentication(PasswordValidator* validator)
    : validator(validator),
masterKeyDerivation(new MasterKeyDerivation()),
kekManager(new KEKManager()) {
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


    try
    {
        std::string longMasterKey = deriveMasterKeyFromPassword(password);
        std::vector<unsigned char> masterKey(longMasterKey.begin(), longMasterKey.begin() + 32);




        auto kek = EncryptionKeyGenerator::generateKey(32);

        qDebug() << "kek:" << kek;
        std::vector<unsigned char> nonce;


        auto encryptedKEK = kekManager->encryptKEK(masterKey, kek, nonce);

        qDebug() << "MasterKey Derived Successfully:" << longMasterKey;
        qDebug() << "User registration successful for:" << username;
        qDebug() << "ENKEK is created: " << encryptedKEK;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        return false;
    }
    
    return true;
}


std::string UserAuthentication::deriveMasterKeyFromPassword(const QString& password)
{
    std::string passwordStr = password.toStdString();

    return masterKeyDerivation->deriveMaster(passwordStr);
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
UserAuthentication::~UserAuthentication()
{
    delete masterKeyDerivation;
    delete kekManager;
}
