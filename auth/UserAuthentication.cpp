#include "UserAuthentication.h"
#include <QDebug>
#include <QJsonDocument>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <sodium.h>
#include <vector>
#include "../key_management/KEKManager.h"
#include "../crypto/crypto_utils.h"
#include "../key_management/KeyEncryptor.h"



static std::vector<unsigned char> masterKeySalt(crypto_pwhash_SALTBYTES);
static std::vector<unsigned char> encryptedKEK;
static std::vector<unsigned char> kekNonce;
static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";

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


bool UserAuthentication::registerUser(const QString& username, const QString& qpassword, const QString& confirmPassword, QString& errorMsg) {
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
        // TODO add functionality to store the salt in keychain after deriving master key

        auto kek = EncryptionKeyGenerator::generateKey(32); //Generates the KEK

        qDebug() << "kek:" << kek;
        kekManager->generateAndStoreUserKeys(kek); // Generates the necessary user keys (identity, signed pre key, one time keys) stores the private keys in OS keychain
        qDebug() << "all stored correctly";
        kekManager->decryptStoredUserKeys(kek); // retrieves and decrypts them here for testing

        kekManager->encryptKEK(masterKey, kek, kekNonce); // Creates the enkek by encrypting with the master key, this now gets stored to keychain under "Enkek"

        // keychain::Error loadError;
        // auto encryptedKEK = kekManager->keyEncryptor_.loadEncryptedKey("Enkek", loadError);
        //
        // qDebug() << "MasterKey Derived Successfully:" << masterKey;
        // qDebug() << "User registration successful for:" << username;
        // qDebug() << "EN_KEK is created: " << encryptedKEK.ciphertext;
        // qDebug() << "KEK Nonce used: " << kekNonce;
        //
        // originalDecryptedKEK = kekManager->decryptKEK(masterKey, encryptedKEK.ciphertext, encryptedKEK.nonce); //Testing purposes
        // qDebug()<< "Decrypted KEK on register: " << originalDecryptedKEK;


    } catch (const std::exception& e) {
        errorMsg = QString("Failed to derive master key: %1").arg(e.what());
        return false;
    }
    
    return true;
}




bool UserAuthentication::loginUser(const QString& username, const QString& qpassword, QString& errorMsg) {
    std::vector<unsigned char> masterKey;
    std::vector<unsigned char> tempdecryptedKEK;        //This is for memory management





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

    KeyEncryptor::EncryptedData encryptedKEKkeychain;
    keychain::Error loadError;
    encryptedKEKkeychain = kekManager->keyEncryptor_.loadEncryptedKey("Enkek", loadError);
    try{
        tempdecryptedKEK = kekManager->decryptKEK(masterKey, encryptedKEKkeychain.ciphertext, encryptedKEKkeychain.nonce);
        qDebug()<< "Decrypted KEK on login: " << tempdecryptedKEK;


    } catch (const std::exception& e) {
        qDebug() << "error decrypting kek Line 117" << e.what();
        return false;
    }

    sodium_memzero(masterKey.data(), masterKey.size());
    masterKey.clear();

    m_currentUsername = username;
    setServerUrl("https:leftovers.gobbler.info.");

    if (!requestChallenge(username))
    {
        sodium_memzero(tempdecryptedKEK.data(), tempdecryptedKEK.size());
        tempdecryptedKEK.clear();
        return false;
    }

    if (currentReply)
    {
        currentReply->setProperty("decryptedKek", QByteArray(reinterpret_cast<const char*>(tempdecryptedKEK.data()), tempdecryptedKEK.size()));
    }else {
        qCritical() << "Error: currentReply is null after requestChallenge. Cannot attach decrypted KEK.";
        // Handle this error appropriately, perhaps emit challengeFailed
        sodium_memzero(tempdecryptedKEK.data(), tempdecryptedKEK.size()); // Wipe even on error
        tempdecryptedKEK.clear();
        return false;
    }

    sodium_memzero(tempdecryptedKEK.data(), tempdecryptedKEK.size());
    tempdecryptedKEK.clear();

    qDebug() << "Login attempt for user:" << username;
    return true;
}


void UserAuthentication::setServerUrl(const QString &url) {
    serverUrl = url;
}

bool UserAuthentication::requestChallenge(const QString &username) {
    qDebug() << "Requesting challenge for user:" << username;

    if (username.isEmpty()) {
        emit challengeFailed("Username cannot be empty.");
        return false;
    }

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

    // SSL configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    request.setSslConfiguration(sslConfig);

    // Send GET request
    currentRequestType = Challenge;
    currentReply = networkManager->get(request);

    // Connect signals
    connect(currentReply, &QNetworkReply::finished,
            this, &UserAuthentication::handleChallengeResponse);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &UserAuthentication::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &UserAuthentication::handleNetworkError);

    return true;
}

bool UserAuthentication::submitLogin(const QString &username, const QByteArray &signature, const QByteArray &nonce) {
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
    QByteArray jsonData = jsonDoc.toJson();

    qDebug() << "Login JSON:" << jsonDoc.toJson(QJsonDocument::Indented);

    // Create network request
    QNetworkRequest request(QUrl(serverUrl + "/auth/login"));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

    // SSL configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    request.setSslConfiguration(sslConfig);

    // Send POST request
    currentRequestType = Login;
    currentReply = networkManager->post(request, jsonData);

    // Connect signals
    connect(currentReply, &QNetworkReply::finished,
            this, &UserAuthentication::handleLoginResponse);
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


                QByteArray decryptedKekQByteArray = currentReply->property("decryptedKek").toByteArray();
                if (decryptedKekQByteArray.isEmpty()) {
                    qCritical() << "Error: Decrypted KEK not found in reply property. Cannot decrypt identity key.";
                    emit challengeFailed("Internal error: KEK not available from reply.");
                    currentReply->deleteLater();
                    currentReply = nullptr;
                    return;
                }
                std::vector<unsigned char> decryptedKekVector(
                    reinterpret_cast<const unsigned char*>(decryptedKekQByteArray.constData()),
                    reinterpret_cast<const unsigned char*>(decryptedKekQByteArray.constData()) + decryptedKekQByteArray.size()
                );
                sodium_memzero(decryptedKekQByteArray.data(), decryptedKekQByteArray.size());
                decryptedKekQByteArray.clear();
                unsigned char signature [crypto_sign_BYTES];
                KeyEncryptor::EncryptedData identityEncrypted;
                keychain::Error loadIdentityError;
                try {
                    identityEncrypted = kekManager->keyEncryptor_.loadEncryptedKey("identityKey", loadIdentityError);
                } catch (const std::exception& e) {
                    qCritical() << "Failed to load encrypted identity key:" << e.what();
                    emit challengeFailed(QString("Failed to load identity key: %1").arg(e.what()));
                    // Wipe KEK even on error
                    sodium_memzero(decryptedKekQByteArray.data(), decryptedKekQByteArray.size());
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
                    nonceBase64.length(),
                    decryptedIdentityPrivateKeyBytes.data()
                    );
                if (result != 0){
                    throw std::runtime_error("Ed25519 signing failed.");
                }
                emit challengeReceived(nonceBytes);
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

    currentReply->deleteLater();
    currentReply = nullptr;
}

void UserAuthentication::handleLoginResponse()
{
    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray response = currentReply->readAll();
        qDebug() << "Login successful. Server response:" << response;
        emit loginSucceeded();
    } else {
        QString errorMsg = QString("Login failed: %1").arg(currentReply->errorString());
        qDebug() << errorMsg;
        emit loginFailed(errorMsg);
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void UserAuthentication::handleSslErrors(const QList<QSslError> &errors) {
    qDebug() << "SSL errors detected, but ignoring for testing:";
    for (const QSslError &error : errors) {
        qDebug() << "  -" << error.errorString();
    }

    if (currentReply) {
        currentReply->ignoreSslErrors();
    }
}

void UserAuthentication::handleNetworkError(QNetworkReply::NetworkError error)
{
    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred during" << (currentRequestType == Challenge ? "challenge" : "login") << ":" << errorString;

    if (currentRequestType == Challenge) {
        emit challengeFailed(errorString);
    } else {
        emit loginFailed(errorString);
    }
}

UserAuthentication::~UserAuthentication()
{

    if (currentReply) {
            currentReply->abort();
            currentReply->deleteLater();
    }

    delete masterKeyDerivation;
}
