#pragma once

#include <QString>
#include <QNetworkAccessManager> // Needed for network operations
#include <QNetworkReply>       // Needed for network replies
#include <QUrl>
#include <QUrlQuery>
#include <QJsonObject>
#include <QByteArray>
#include "validation.h"
#include "../key_management/MasterKeyDerivation.h"
#include "../key_management/EncryptionKeyGenerator.h"
#include "../key_management/KEKManager.h"

enum RequestType {
    Challenge,
    Login
};

class UserAuthentication : public QObject{
    Q_OBJECT
public:
    UserAuthentication(PasswordValidator* validator, QObject *parent = nullptr);
    ~UserAuthentication();
    static constexpr int DEFAULT_ONETIME_KEYS = 10;
    
    // Register a new user
    bool registerUser(const QString& username, const QString&  qpassword, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);

    void setServerUrl(const QString &url);
    bool requestChallenge(const QString &username);
    bool submitLogin(const QString &username, const QByteArray &signature, const QByteArray &nonce);

    signals:
    void challengeReceived(const QByteArray &nonce);
    void challengeFailed(const QString &error);
    void loginSucceeded();
    void loginFailed(const QString &error);

private slots:
    void handleChallengeResponse();
    void handleLoginResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    PasswordValidator* validator;
    MasterKeyDerivation* masterKeyDerivation;
    EncryptionKeyGenerator* encryptionKeyGenerator;
    KEKManager* kekManager;

    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    RequestType currentRequestType;
    QString serverUrl;
    QString m_currentUsername; // To store username across async calls
    QString m_originalNonceBase64; // To store the original nonce string

    std::vector<unsigned char> m_decryptedKek;



    std::string deriveMasterKeyFromPassword(const QString& password, const std::vector<unsigned char>& salt);
    bool generateAndRegisterX3DHKeys(const QString& username, const std::vector<unsigned char>& kek, QString& errorMsg);

    // TODO: Add database connection or storage mechanism
};
