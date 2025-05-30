#include "UserAuthentication.h"
#include <QDebug>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium.h>
#include <vector>
#include "../key_management/KEKManager.h"
#include "../FrontEnd/RegisterPage/registerManager.h"
#include "../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../key_management/X3DHKeys/OneTimeKeyPair.h"
#include "../key_management/KeyEncryptor.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>


static std::vector<unsigned char> masterKeySalt(crypto_pwhash_SALTBYTES);
static std::vector<unsigned char> encryptedKEK;
static std::vector<unsigned char> kekNonce;

// These are members to store registration state
static RegisterManager* registerManager = nullptr;


UserAuthentication::UserAuthentication(PasswordValidator* validator)
    : validator(validator),
masterKeyDerivation(new MasterKeyDerivation()),
kekManager(new KEKManager()) {
}

bool UserAuthentication::registerUserLocally(const QString& username, const QString& qpassword, const QString& confirmPassword, QString& errorMsg) {
    std::vector<unsigned char> originalDecryptedKEK;

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
        randombytes_buf(masterKeySalt.data(), masterKeySalt.size());

        std::vector<unsigned char> masterKey = masterKeyDerivation->deriveMaster(password, masterKeySalt); //Uses Argon2id

        auto kek = EncryptionKeyGenerator::generateKey(32); //Generates the KEK

        qDebug() << "kek:" << kek;
        KEKManager::generateAndStoreUserKeys(kek, DEFAULT_ONETIME_KEYS); // Generates and stores user keys

        encryptedKEK = kekManager->encryptKEK(masterKey, kek, kekNonce);

        qDebug() << "MasterKey Derived Successfully:" << masterKey;
        qDebug() << "EN_KEK is created: " << encryptedKEK;
        qDebug() << "KEK Nonce used: " << kekNonce;

        originalDecryptedKEK = kekManager->decryptKEK(masterKey, encryptedKEK, kekNonce);
        qDebug()<< "Decrypted KEK on register: " << originalDecryptedKEK;

        if (!generateAndRegisterX3DHKeys(username, kek, errorMsg)) {
            return false;
        }

        qDebug() << "User registration successful for:" << username;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        return false;
    }
    
    return true;
}

bool UserAuthentication::generateAndRegisterX3DHKeys(const QString& username, const std::vector<unsigned char>& kek, QString& errorMsg) {
    try {
        DecryptedKeyData storedKeys = KEKManager::decryptStoredUserKeys(kek);

        // Extract public keys from private keys using libsodium functions
        std::vector<unsigned char> identityPublicKey(crypto_sign_PUBLICKEYBYTES);
        std::vector<unsigned char> signedPrePublicKey(crypto_box_PUBLICKEYBYTES);

        // For Ed25519 (identity key), extract public key from private key
        if (crypto_sign_ed25519_sk_to_pk(identityPublicKey.data(), storedKeys.identityPrivateKey.data()) != 0) {
            errorMsg = "Failed to extract identity public key from private key";
            return false;
        }
        // For X25519 (signed prekey), extract public key from private key
        if (crypto_scalarmult_base(signedPrePublicKey.data(), storedKeys.signedPreKeyPrivate.data()) != 0) {
            errorMsg = "Failed to extract signed prekey public key from private key";
            return false;
        }
        // Create signature for the signed prekey using the stored identity private key
        std::vector<unsigned char> signedPreKeySignature(crypto_sign_BYTES);
        unsigned long long sig_len;
        if (crypto_sign_detached(signedPreKeySignature.data(), &sig_len,
                                 signedPrePublicKey.data(), signedPrePublicKey.size(),
                                 storedKeys.identityPrivateKey.data()) != 0) {
            errorMsg = "Failed to sign the prekey";
            return false;
        }

        // Generate one-time keys
        QJsonArray oneTimeKeysArray;
        for (const auto &oneTimePrivateKey: storedKeys.oneTimeKeyPrivates) {
            std::vector<unsigned char> oneTimePublicKey(crypto_box_PUBLICKEYBYTES);

            // Extract public key from private key
            if (crypto_scalarmult_base(oneTimePublicKey.data(), oneTimePrivateKey.data()) != 0) {
                errorMsg = "Failed to extract one-time public key from private key";
                return false;
            }

            QByteArray keyBytes(reinterpret_cast<const char *>(oneTimePublicKey.data()), oneTimePublicKey.size());
            QString base64Key = QString::fromLatin1(keyBytes.toBase64());
            oneTimeKeysArray.append(base64Key);
        }
        qDebug() << "Generated" << oneTimeKeysArray.size() << "one-time keys (expected:" << DEFAULT_ONETIME_KEYS << ")";

        // Create JSON payload for server registration
        QJsonObject registrationData;
        registrationData["username"] = username;
        registrationData["identityPublicKey"] = QString::fromLatin1(
                QByteArray(reinterpret_cast<const char *>(identityPublicKey.data()),
                           identityPublicKey.size()).toBase64());
        registrationData["signedPreKeyPublicKey"] = QString::fromLatin1(
                QByteArray(reinterpret_cast<const char *>(signedPrePublicKey.data()),
                           signedPrePublicKey.size()).toBase64());
        registrationData["signedPreKeySignature"] = QString::fromLatin1(
                QByteArray(reinterpret_cast<const char *>(signedPreKeySignature.data()),
                           signedPreKeySignature.size()).toBase64());
        registrationData["oneTimeKeys"] = oneTimeKeysArray;

        // Create RegisterManager instance and register with server
        if (!registerManager) {
            registerManager = new RegisterManager();
            registerManager->setServerUrl("https://leftovers.gobbler.info");
        }
        qDebug() << "Using stored keys for server registration:";
        qDebug() << "Identity Public Key:" << registrationData["identityPublicKey"].toString();
        qDebug() << "Number of one-time keys:" << oneTimeKeysArray.size();


        // Register with server
        return registerManager->sendRegistrationData(registrationData);

    } catch (const std::exception &e) {
        errorMsg = QString("Failed to generate X3DH keys: %1").arg(e.what());
        return false;
    }
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
        masterKey = masterKeyDerivation->deriveMaster(password, masterKeySalt); //Uses Argon2id
        qDebug() << "Master Key on login: " << masterKey;


    } catch (const std::exception& e) {
        errorMsg = QString("Login failed during key derivation: %1").arg(e.what());
        qDebug() << "Exception during masterKey derivation in login:" ;
        return false;
    }

    //GETS DECRYPTED KEY ENCYPTION KEY
    try{
        decryptedKEK = kekManager->decryptKEK(masterKey, encryptedKEK, kekNonce);
        qDebug()<< "Decrypted KEK on login: " << decryptedKEK;

    } catch (const std::exception& e) {
        qDebug() << "error decrypting kek Line 117" << e.what();
        return false;
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
