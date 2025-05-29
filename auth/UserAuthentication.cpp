#include "UserAuthentication.h"
#include <QDebug>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium.h>
#include <vector>
#include "../key_management/KEKManager.h"


static std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
static std::vector<unsigned char> encryptedKEK;
static std::vector<unsigned char> nonce;

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
      //  std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES); // 16 byte salt
        randombytes_buf(salt.data(), salt.size());

        std::vector<unsigned char> masterKey = masterKeyDerivation->deriveMaster(password, salt); //Uses Argon2id

        auto kek = EncryptionKeyGenerator::generateKey(32); //Generates the KEK

        qDebug() << "kek:" << kek;
        KEKManager::generateAndStoreUserKeys(kek);
        std::vector<unsigned char> nonce;

        KEKManager::decryptAndStoredUserKeys(kek);

        // auto encryptedKEK = kekManager->encryptKEK(masterKey, kek, nonce);
        encryptedKEK = kekManager->encryptKEK(masterKey, kek, nonce);

        qDebug() << "MasterKey Derived Successfully:" << masterKey;
        qDebug() << "User registration successful for:" << username;
        qDebug() << "ENKEK is created: " << encryptedKEK;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        return false;
    }
    
    return true;
}



bool UserAuthentication::loginUser(const QString& username, const QString& qpassword, QString& errorMsg) {
    std::vector<unsigned char> masterKey;
    std::vector<unsigned char> decryptedKEK;


    //for testing purposes


    //validates username
    if (!validator->validateUsername(username, errorMsg)) {
        return false;
    }



    std::string password = qpassword.toStdString();
    qDebug() << password << "LINE 89";



    //GETS MASTERKEY
    try {
        //gets masterkey from password by passing it and the salt into argon2
        masterKey = masterKeyDerivation->deriveMaster(password, salt); //Uses Argon2id
        qDebug() << masterKey;


    } catch (const std::exception& e) {
        errorMsg = QString("Login failed during key derivation: %1").arg(e.what());
        qDebug() << "Exception during masterKey derivation in login:" ;
        return false;
    }



    //GETS DECRYPTED KEY ENCYPTION KEY
    try{
        decryptedKEK = kekManager->decryptKEK(masterKey, encryptedKEK, nonce);
        qDebug() << "inside here";
        qDebug() << decryptedKEK << "Line 113";
        qDebug() << "inside here";

    } catch (const std::exception& e) {
        qDebug() << "error decrypting kek Line 117" << e.what();
    }



    qDebug() << encryptedKEK << "LINE 122";




    qDebug() << "Login attempt for user:" << username;
    
    // TODO: Check credentials against database
    
    return true;
}
UserAuthentication::~UserAuthentication()
{
    delete masterKeyDerivation;
    delete kekManager;
}
