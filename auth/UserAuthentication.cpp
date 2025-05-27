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

bool UserAuthentication::changePassword(const QString& currentPassword, const QString& newPassword, const QString& confirmNewPassword, QString& errorMsg) {
    // Validate current password is not empty
    if (currentPassword.isEmpty()) {
        errorMsg = "Current password cannot be empty";
        return false;
    }
    
    // TODO: Verify current password against stored credentials
    // For now, we'll simulate this check
    if (currentPassword.length() < 1) {
        errorMsg = "Current password is incorrect";
        return false;
    }
    
    // Validate new password using existing validation logic
    if (!validator->validatePassword(newPassword, confirmNewPassword, errorMsg)) {
        return false;
    }
    
    // Check that new password is different from current password
    if (currentPassword == newPassword) {
        errorMsg = "New password must be different from current password";
        return false;
    }
    
    std::string newPasswordStr = newPassword.toStdString();
    
    try {
        // Generate new salt for the new password
        std::vector<unsigned char> newSalt(crypto_pwhash_SALTBYTES);
        randombytes_buf(newSalt.data(), newSalt.size());
        
        // Derive new master key from new password
        std::vector<unsigned char> newMasterKey = masterKeyDerivation->deriveMaster(newPasswordStr, newSalt);
        
        // Generate new KEK
        auto newKek = EncryptionKeyGenerator::generateKey(32);
        
        std::vector<unsigned char> nonce;
        auto encryptedNewKEK = kekManager->encryptKEK(newMasterKey, newKek, nonce);
        
        qDebug() << "Password change successful - New MasterKey derived:" << newMasterKey;
        qDebug() << "New encrypted KEK created:" << encryptedNewKEK;
        
        // TODO: Update stored credentials in database
        // TODO: Re-encrypt existing data with new keys if necessary
        
    } catch (const std::exception& e) {
        errorMsg = QString("Failed to change password: %1").arg(e.what());
        return false;
    }
    
    return true;
}

UserAuthentication::~UserAuthentication()
{
    delete masterKeyDerivation;
    delete kekManager;
}
