#include "UserAuthentication.h"
#include <QDebug>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium.h>
#include <vector>

UserAuthentication::UserAuthentication(PasswordValidator* validator)
    : validator(validator),
masterKeyDerivation(new MasterKeyDerivation()),
kekManager(new KEKManager()) {
}

bool UserAuthentication::registerUser(const QString& username, const QString& qpassword, const QString& confirmPassword, QString& errorMsg) {
    // Validate username
    if (!validator->validateUsername(username, errorMsg)) {
        return false;
    }
    
    // Validate password
    if (!validator->validatePassword(qpassword, confirmPassword, errorMsg)) {
        return false;
    }

    std::string password = qpassword.toStdString();

    try
    {
        std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES); // 16 byte salt
        randombytes_buf(salt.data(), salt.size());

        std::vector<unsigned char> masterKey = masterKeyDerivation->deriveMaster(password, salt); //Uses Argon2id

        auto kek = EncryptionKeyGenerator::generateKey(32); //Generates the KEK

        qDebug() << "kek:" << kek;
        std::vector<unsigned char> nonce;

        auto encryptedKEK = kekManager->encryptKEK(masterKey, kek, nonce);

        qDebug() << "MasterKey Derived Successfully:" << masterKey;
        qDebug() << "User registration successful for:" << username;
        qDebug() << "ENKEK is created: " << encryptedKEK;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        return false;
    }
    
    return true;
}



bool UserAuthentication::loginUser(const QString& username, const QString& password, QString& errorMsg) {
   


    // For now, return success if username and password are not empty
    if(username.isEmpty() || password.isEmpty()) {
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
