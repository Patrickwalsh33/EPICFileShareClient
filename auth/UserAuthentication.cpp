#include "UserAuthentication.h"

#include <iostream>
#include <QDebug>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium.h>
#include <vector>
#include "../key_management/KEKManager.h"
#include "../crypto/crypto_utils.h"
#include "../key_management/KeyEncryptor.h"
#include "../FrontEnd/RegisterPage/registerManager.h"
#include "../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../key_management/X3DHKeys/OneTimeKeyPair.h"
#include "../key_management/KeyEncryptor.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QJsonDocument>
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include "keychain/keychain.h"
#include <string>
#include "../FrontEnd/SessionManager/SessionManager.h"






static std::vector<unsigned char> encryptedKEK;
static std::vector<unsigned char> kekNonce;
static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";
keychain::Error keychainError;
keychain::Error loadError;



UserAuthentication::UserAuthentication(PasswordValidator* validator,const std::string& appPackage, const std::string& appUser, QObject *parent)
    : QObject(parent),
    validator(validator),
    masterKeyDerivation(new MasterKeyDerivation()),
    kekManager(std::make_unique<KEKManager>(appPackage, appUser)),
    networkManager(new QNetworkAccessManager(this)),
    currentReply(nullptr),
    currentRequestType(Challenge)
{
    qDebug() << "UserAuthentication created with appPackage:" << QString::fromStdString(appPackage);
    qDebug() << "UserAuthentication created with appUser:" << QString::fromStdString(appUser);
    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system";
    }
}

static RegisterManager* registerManager = nullptr;




bool UserAuthentication::registerUser(const QString& username, const QString& qpassword, const QString& confirmPassword, QString& errorMsg) {
    std::vector<unsigned char> originalDecryptedKEK;
    std::vector<unsigned char> masterKeySalt(crypto_pwhash_SALTBYTES);


    // Validate username
    if (!validator->validateUsername(username, errorMsg)) {
        emit registrationFailed(errorMsg);
        return false;
    }
    
    // Validate password
    if (!validator->validatePassword(qpassword, confirmPassword, errorMsg)) {
        emit registrationFailed(errorMsg);
        return false;
    }

    std::string password = qpassword.toStdString();

    try
    {

        randombytes_buf(masterKeySalt.data(), masterKeySalt.size());
        qDebug() << "Original salt (hex):" << QByteArray(reinterpret_cast<const char*>(masterKeySalt.data()), masterKeySalt.size()).toHex();


        std::vector<unsigned char> masterKey = masterKeyDerivation->deriveMaster(password, masterKeySalt); //Uses Argon2id
        std::string saltEncoded = base64Encode(masterKeySalt);
        qDebug() << "Encoded salt (base64):" << QString::fromStdString(saltEncoded);
        keychain::setPassword(package1, "MasterKeySalt", user1, saltEncoded, keychainError);

        auto kek = EncryptionKeyGenerator::generateKey(32); //Generates the KEK

        qDebug() << "kek:" << kek;

        kekManager->generateAndStoreUserKeys(kek); // Generates the necessary user keys (identity, signed pre key, one time keys) stores the private keys in OS keychain
        qDebug() << "all stored correctly";
        kekManager->decryptStoredUserKeys(kek); // retrieves and decrypts them here for testing

        kekManager->encryptKEK(masterKey, kek, kekNonce); // Creates the enkek by encrypting with the master key, this now gets stored to keychain under "Enkek"


        if (!generateAndRegisterX3DHKeys(username, kek, errorMsg)) {
            emit registrationFailed(errorMsg);
            return false;
        }

        qDebug() << "User registration successful for:" << username;
        emit registrationSucceeded();
        return true;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        emit registrationFailed(errorMsg);
        return false;
    }
    
    return true;
}

bool UserAuthentication::generateAndRegisterX3DHKeys(const QString& username, const std::vector<unsigned char>& kek, QString& errorMsg) {
    try {
        DecryptedKeyData storedKeys = kekManager->decryptStoredUserKeys(kek);

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

    if(!rateLimiter.canAttemptLogin()){
        errorMsg =  "Too many attempts. Wait 5 minutes";
        return false;
    }
    std::vector<unsigned char> masterKeyOnLogin;

    std::vector<unsigned char> tempdecryptedKEK;


    //validates username
    if (!validator->validateUsername(username, errorMsg)) {
        return false;
    }

    std::string password = qpassword.toStdString();
    qDebug() << password << "LINE 89";


    //GETS MASTERKEY
    try {


        auto saltEncoded = keychain::getPassword(package1, "MasterKeySalt", user1, keychainError);
        qDebug() << "Encoded salt (base64):" << QString::fromStdString(saltEncoded);


// Convert string back to original salt
        std::vector<unsigned char> saltDecoded = base64Decode(saltEncoded);
        qDebug() << "Decoded salt (hex):" << QByteArray(reinterpret_cast<const char*>(saltDecoded.data()), saltDecoded.size()).toHex();


        masterKeyOnLogin = masterKeyDerivation->deriveMaster(password, saltDecoded);


        //gets masterkey from password by passing it and the salt into argon2
        qDebug() << "Master Key on login: " << masterKeyOnLogin;


    } catch (const std::exception& e) {
        errorMsg = QString("Login failed during key derivation: %1").arg(e.what());
        qDebug() << "Exception during masterKey derivation in login:" ;
        return false;
    }

    //GETS DECRYPTED KEY ENCYPTION KEY

    KeyEncryptor::EncryptedData encryptedKEKkeychain;
    encryptedKEKkeychain = kekManager->keyEncryptor_.loadEncryptedKey("Enkek", loadError);
    try{

        tempdecryptedKEK = kekManager->decryptKEK(masterKeyOnLogin, encryptedKEKkeychain.ciphertext, encryptedKEKkeychain.nonce);
        qDebug()<< "Decrypted KEK on login: " << tempdecryptedKEK;

        m_decryptedKekTemp = QByteArray(
                   reinterpret_cast<const char*>(tempdecryptedKEK.data()), tempdecryptedKEK.size());

        // Store the KEK in SessionManager
        SessionManager::getInstance()->setDecryptedKEK(m_decryptedKekTemp);

        sodium_memzero(tempdecryptedKEK.data(), tempdecryptedKEK.size());
        tempdecryptedKEK.clear();
        sodium_memzero(masterKeyOnLogin.data(), masterKeyOnLogin.size());
        masterKeyOnLogin.clear();

    } catch (const std::exception& e) {
        qDebug() << "error decrypting kek " << e.what();
        return false;
    }

    qDebug() << "Login attempt for user:" << username;

    
    return requestChallenge(username);
}



void UserAuthentication::setServerUrl(const QString &url) {
    serverUrl = url;
}

bool UserAuthentication::requestChallenge(const QString &username) {
    setServerUrl("https://leftovers.gobbler.info");
    qDebug() << "Requesting challenge for user:" << username;
    m_currentUsername = username;

    if (username.isEmpty()) {
        emit challengeFailed("Username cannot be empty.");
        return false;
    }
    qDebug() << "username is set now sending request to " << serverUrl;
    if (serverUrl.isEmpty()) {
        emit challengeFailed("Server URL is not set.");
        return false;
    }

    // Create URL with username parameter
    QUrl url(serverUrl + "/auth/challenge");
    QUrlQuery query;
    query.addQueryItem("username", username);
    url.setQuery(query);

    qDebug() << "Challenge URL:" << url.toString();

    // Create network request
    QNetworkRequest request(url);
    qDebug() << "Network request:" << request.url();

    // SSL configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    // Send GET request
    currentRequestType = Challenge;
    currentReply = networkManager->get(request);
    qDebug() << "Challenge request sent";


    // Connect signals
    connect(currentReply, &QNetworkReply::finished,
            this, &UserAuthentication::handleChallengeResponse);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &UserAuthentication::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &UserAuthentication::handleNetworkError);

    return true;
}

void UserAuthentication::handleChallengeResponse()
{
    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray response = currentReply->readAll();
        qDebug() << "Challenge response received:" << response;

        // Parse JSON response to extract nonce
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response);
        if (jsonDoc.isObject()) {
            QJsonObject jsonObj = jsonDoc.object();
            if (jsonObj.contains("nonce")) {
                QString nonceBase64 = jsonObj["nonce"].toString();
                // Stores the raw nonce bytes for signing
                QByteArray nonceBytes = QByteArray::fromBase64(nonceBase64.toLatin1());
                qDebug() << "Received nonce (Base64):" << nonceBase64;



                std::vector<unsigned char> decryptedKekVector(
                    reinterpret_cast<const unsigned char*>(m_decryptedKekTemp.constData()),
                    reinterpret_cast<const unsigned char*>(m_decryptedKekTemp.constData()) + m_decryptedKekTemp.size()
                );

                unsigned char signature [crypto_sign_BYTES];
                KeyEncryptor::EncryptedData identityEncrypted;
                keychain::Error loadIdentityError;
                try {
                    identityEncrypted = kekManager->keyEncryptor_.loadEncryptedKey("identityKey", loadIdentityError);
                } catch (const std::exception& e) {
                    qCritical() << "Failed to load encrypted identity key:" << e.what();
                    emit challengeFailed(QString("Failed to load identity key: %1").arg(e.what()));
                    // Wipe KEK even on error
                    sodium_memzero(m_decryptedKekTemp.data(), m_decryptedKekTemp.size());
                    return;
                }


                std::vector<unsigned char> decryptedIdentityPrivateKeyBytes;
                try {
                    decryptedIdentityPrivateKeyBytes = KeyEncryptor::decrypt(identityEncrypted, decryptedKekVector);

                    // Check if the decrypted key has the correct size for Ed25519 secret key
                    if (decryptedIdentityPrivateKeyBytes.size() != crypto_sign_SECRETKEYBYTES) {
                        throw std::runtime_error("Decrypted identity key has incorrect size for Ed25519 secret key.");
                    }
                } catch (const std::exception& e) {
                    qCritical() << "Failed to decrypt identity private key:" << e.what();
                    emit challengeFailed(QString("Failed to decrypt identity key: %1").arg(e.what()));
                    // Wipe KEK vector even on error
                    sodium_memzero(decryptedKekVector.data(), decryptedKekVector.size());
                    decryptedKekVector.clear();
                    return;
                }

                int result = crypto_sign_ed25519_detached(
                    signature,
                    NULL,
                    reinterpret_cast<const unsigned char*>(nonceBytes.constData()),
                    nonceBytes.size(),
                    decryptedIdentityPrivateKeyBytes.data()
                    );
                if (result != 0){
                    throw std::runtime_error("Ed25519 signing failed.");
                }
                sodium_memzero(decryptedIdentityPrivateKeyBytes.data(), decryptedIdentityPrivateKeyBytes.size());
                decryptedIdentityPrivateKeyBytes.clear();

                QByteArray signatureBytes(reinterpret_cast<const char*>(signature), crypto_sign_BYTES);
                qDebug() << "Ed25519 signature received:" << signatureBytes;
                qDebug() << "Ed25519 nonce bytes:"<< nonceBytes;
                qDebug()<< "calling submit signed challenge for: "<< m_currentUsername;
                submitSignedChallenge(m_currentUsername, signatureBytes, nonceBytes);

            } else {
                emit challengeFailed("Invalid response: nonce not found");
            }
        } else {
            emit challengeFailed("Invalid JSON response");
        }
    } else {
        QString errorMsg = QString("Challenge request failed: %1").arg(currentReply->errorString());
        qDebug() << errorMsg;
        emit challengeFailed(errorMsg);
    }



}

bool UserAuthentication::submitSignedChallenge(const QString &username, const QByteArray &signature, const QByteArray &nonce) {
    qDebug() << "Submitting login for user:" << username;

    if (username.isEmpty()) {
        emit loginFailed("Username cannot be empty.");
        return false;
    }

    if (signature.isEmpty() || nonce.isEmpty()) {
        emit loginFailed("Signature and nonce are required.");
        return false;
    }

    if (serverUrl.isEmpty()) {
        emit loginFailed("Server URL is not set.");
        return false;
    }

    // Create JSON payload
    QJsonObject loginData;
    loginData["username"] = username;
    loginData["signature"] = QString::fromLatin1(signature.toBase64());
    loginData["nonce"] = QString::fromLatin1(nonce.toBase64());

    QJsonDocument jsonDoc(loginData);
    QByteArray jsonData = jsonDoc.toJson(QJsonDocument::Compact);

    qDebug() << "Login JSON:" << jsonDoc.toJson(QJsonDocument::Compact);

    qDebug() << "Sending challenge to :" << serverUrl;
    qDebug() << "--- RAW JSON DATA BEING SENT (HEX DUMP) ---";
    qDebug() << jsonData.toHex();
    qDebug() << "--- END RAW JSON DATA ---";

    // Create network request
    QNetworkRequest request(QUrl (serverUrl + "/auth/login"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    // SSL configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);


    // Send POST request
    currentRequestType = Login;
    currentReply = networkManager->post(request, jsonData);
    qDebug() << "Response sent successfully"<< currentReply;


    // Connect signals
    connect(currentReply, &QNetworkReply::finished,
            this, &UserAuthentication::handleLoginResponse);
    qDebug() << "handleloginresponse";
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &UserAuthentication::handleSslErrors);
    qDebug() << "sslErrors";
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &UserAuthentication::handleNetworkError);
    qDebug() << "network error";

    return true;
}


void UserAuthentication::handleLoginResponse()
{
    qDebug() << "handleLoginResponse triggered.";
    if (currentReply->error() != QNetworkReply::NoError) {
        qDebug() << "Login Reply Error:" << currentReply->errorString();
        // Clear KEK from SessionManager on login failure after challenge was passed
        if (currentRequestType == Login) {
            SessionManager::getInstance()->clearSessionData();
        }
    } else {
        qDebug() << "Login Reply Success.";
        rateLimiter.loginSuccess();
    }
    if (currentReply->error() == QNetworkReply::NoError)
    {
        QByteArray response = currentReply->readAll();
        QJsonDocument jsonDoc = QJsonDocument::fromJson(response);
        if (jsonDoc.isObject())
        {
            QJsonObject jsonObj = jsonDoc.object();
            if (jsonObj.contains("access_token"))
            {
                QString accessTokenQString = jsonObj["access_token"].toString();

                //Convert the QString to a QByteArray (UTF-8 encoded)
                QByteArray accessTokenByteArray = accessTokenQString.toUtf8();

                SessionManager::getInstance()->setAccessToken(accessTokenByteArray);

                //Convert the QByteArray to a std::string
                std::string accessTokenStdString = accessTokenByteArray.toStdString();

                std::cout << accessTokenStdString << std::endl;


                QByteArray rawAccessToken = jsonObj["access_token"].toVariant().toByteArray();

                qDebug() << "Raw Access Token:" << rawAccessToken;

                qDebug() << "Access token stored in member variable.";

                emit loginSucceeded(m_currentUsername);
            }else
                qDebug() << "Login successful. but access_token not found in response" << response;
        }else
        {
            QString errorMsg = "Login successful, but invalid JSON response received.";
            qWarning() << errorMsg;
            // Clear KEK from SessionManager on login failure
            SessionManager::getInstance()->clearSessionData();
            emit loginFailed(errorMsg);
        }
    } else {
        QString errorMsg = QString("Login failed: %1").arg(currentReply->errorString());
        qDebug() << errorMsg;
        // Clear KEK from SessionManager on login failure
        SessionManager::getInstance()->clearSessionData();
        emit loginFailed(errorMsg);
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

QString UserAuthentication::getAccessToken() const {
    return m_accessToken;
}
QByteArray UserAuthentication::getDecryptedKekTemp() const{
    return m_decryptedKekTemp;
}

void UserAuthentication::handleSslErrors(const QList<QSslError> &errors) {
    qDebug() << "handleSslErrors triggered.";
    for (const QSslError &error : errors) {
        qDebug() << "SSL Error:" << error.errorString();
    }
    currentReply->ignoreSslErrors(errors);
}

void UserAuthentication::handleNetworkError(QNetworkReply::NetworkError error)
{

    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred during" << (currentRequestType == Challenge ? "challenge" : "login") << ":" << errorString;


    // clear the KEK from session as login is not fully successful.
    if (currentRequestType == Login) {
        SessionManager::getInstance()->clearSessionData();
    }

    if (currentRequestType == Challenge) {
        emit challengeFailed(errorString);
    } else {
        emit loginFailed(errorString);
    }
}

QByteArray UserAuthentication::deriveKeyFromPassword(const QString& password) {
    qDebug() << "Deriving master key from password using Argon2";
    
    // Get stored salt from keychain
    auto saltEncoded = keychain::getPassword(package1, "MasterKeySalt", user1, loadError);
    if (loadError.type != keychain::ErrorType::NoError) {
        throw std::runtime_error("Failed to load master key salt from keychain");
    }
    qDebug() << "Loaded salt (base64):" << QString::fromStdString(saltEncoded);

    // Convert string back to original salt
    std::vector<unsigned char> salt = base64Decode(saltEncoded);
    qDebug() << "Decoded salt (hex):" << QByteArray(reinterpret_cast<const char*>(salt.data()), salt.size()).toHex();
    
    // Convert password to byte array
    QByteArray passwordBytes = password.toUtf8();
    
    // Use Argon2 to derive key with MODERATE parameters (same as login)
    std::vector<unsigned char> derivedKey(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(derivedKey.data(), derivedKey.size(),
                     passwordBytes.constData(), passwordBytes.size(),
                     salt.data(),
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Failed to derive key from password - out of memory");
    }

    qDebug() << "Derived master key (hex):" << QByteArray(reinterpret_cast<const char*>(derivedKey.data()), derivedKey.size()).toHex();
    
    return QByteArray(reinterpret_cast<const char*>(derivedKey.data()), derivedKey.size());
}

QByteArray UserAuthentication::deriveNewKeyFromPassword(const QString& password) {
    qDebug() << "Deriving new master key from password using Argon2";
    
    // Generate new salt
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());
    
    // Store new salt in keychain
    std::string saltEncoded = base64Encode(salt);
    keychain::setPassword(package1, "MasterKeySalt", user1, saltEncoded, keychainError);
    if (keychainError.type != keychain::ErrorType::NoError) {
        throw std::runtime_error("Failed to store new master key salt");
    }
    qDebug() << "New salt stored (base64):" << QString::fromStdString(saltEncoded);
    
    // Convert password to byte array
    QByteArray passwordBytes = password.toUtf8();
    
    // Use Argon2 to derive key with MODERATE parameters (same as login)
    std::vector<unsigned char> derivedKey(crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    if (crypto_pwhash(derivedKey.data(), derivedKey.size(),
                     passwordBytes.constData(), passwordBytes.size(),
                     salt.data(),
                     crypto_pwhash_OPSLIMIT_MODERATE,
                     crypto_pwhash_MEMLIMIT_MODERATE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Failed to derive key from password - out of memory");
    }

    qDebug() << "New master key (hex):" << QByteArray(reinterpret_cast<const char*>(derivedKey.data()), derivedKey.size()).toHex();
    
    return QByteArray(reinterpret_cast<const char*>(derivedKey.data()), derivedKey.size());
}

QByteArray UserAuthentication::decryptKEK(const QByteArray& masterKey) {
    qDebug() << "Decrypting KEK with master key";
    
    // Get encrypted KEK from keychain
    KEKManager kekManager(package1, user1);  // Use the static constants
    std::vector<unsigned char> masterKeyVec(reinterpret_cast<const unsigned char*>(masterKey.constData()),
                                          reinterpret_cast<const unsigned char*>(masterKey.constData()) + masterKey.size());
    
    try {
        KeyEncryptor::EncryptedData encryptedKEK = kekManager.keyEncryptor_.loadEncryptedKey("Enkek", loadError);
        return QByteArray(reinterpret_cast<const char*>(kekManager.decryptKEK(masterKeyVec, encryptedKEK.ciphertext, encryptedKEK.nonce).data()),
                         kekManager.decryptKEK(masterKeyVec, encryptedKEK.ciphertext, encryptedKEK.nonce).size());
    } catch (const std::exception& e) {
        qDebug() << "Failed to decrypt KEK:" << e.what();
        throw;
    }
}

bool UserAuthentication::updateKEKEncryption(const QByteArray& decryptedKEK, const QByteArray& newMasterKey) {
    qDebug() << "Re-encrypting KEK with new master key";
    
    try {
        KEKManager kekManager(package1, user1);  // Use the static constants
        std::vector<unsigned char> kekVec(reinterpret_cast<const unsigned char*>(decryptedKEK.constData()),
                                        reinterpret_cast<const unsigned char*>(decryptedKEK.constData()) + decryptedKEK.size());
        std::vector<unsigned char> newKeyVec(reinterpret_cast<const unsigned char*>(newMasterKey.constData()),
                                           reinterpret_cast<const unsigned char*>(newMasterKey.constData()) + newMasterKey.size());
        
        // Generate new nonce
        std::vector<unsigned char> nonce(crypto_aead_chacha20poly1305_NPUBBYTES);
        randombytes_buf(nonce.data(), nonce.size());
        
        // Encrypt and store the KEK
        kekManager.encryptKEK(newKeyVec, kekVec, nonce);
        return true; // If we get here, encryption succeeded
    } catch (const std::exception& e) {
        qDebug() << "Failed to update KEK encryption:" << e.what();
        return false;
    }
}

bool UserAuthentication::verifyMasterKey(const QByteArray& masterKey) {
    try {
        // Try to decrypt KEK with the master key
        QByteArray decryptedKEK = decryptKEK(masterKey);
        return !decryptedKEK.isEmpty();
    } catch (const std::exception& e) {
        qDebug() << "Master key verification failed:" << e.what();
        return false;
    }
}

UserAuthentication::~UserAuthentication()
{
    delete masterKeyDerivation;
}