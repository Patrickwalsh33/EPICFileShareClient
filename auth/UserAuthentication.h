#pragma once

#include <QString>
#include <QObject>
#include <QUrlQuery>
#include "validation.h"
#include "../key_management/MasterKeyDerivation.h"
#include "../key_management/EncryptionKeyGenerator.h"
#include "../key_management/KEKManager.h"
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonArray>
#include <QNetworkRequest>
#include <QSslError>



class UserAuthentication : public QObject {
    Q_OBJECT

public:
    UserAuthentication(PasswordValidator* validator, const std::string& appPackage, const std::string& appUser, QObject *parent = nullptr);
    ~UserAuthentication();


    static constexpr int DEFAULT_ONETIME_KEYS = 10;
    
    // Register a new user
    bool registerUser(const QString& username, const QString&  qpassword, const QString& confirmPassword, QString& errorMsg);
    
    // Login a user
    bool loginUser(const QString& username, const QString& password, QString& errorMsg);
    
    // Network methods
    void setServerUrl(const QString &url);
    QString getAccessToken() const;
    QByteArray getDecryptedKekTemp() const;


signals:
    void challengeFailed(const QString &error);
    void challengeReceived(const QByteArray &nonce);
    void loginFailed(const QString &error);
    void loginSucceeded(const QString &username);


private slots:
    void handleChallengeResponse();
    void handleLoginResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    bool requestChallenge(const QString &username);
    bool submitSignedChallenge(const QString &username, const QByteArray &signature, const QByteArray &nonce);

    PasswordValidator* validator;
    MasterKeyDerivation* masterKeyDerivation;
    EncryptionKeyGenerator* encryptionKeyGenerator;
    std::unique_ptr<KEKManager> kekManager;

    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    // RequestType currentRequestType;
    QString serverUrl;
    QString m_currentUsername; // To store username across async calls
    QString m_originalNonceBase64; // To store the original nonce string
    QString m_accessToken; //Store the JWT access token

    QByteArray m_decryptedKekTemp;
    std::string appPackage_;
    std::string appUser_;

    std::string deriveMasterKeyFromPassword(const QString& password, const std::vector<unsigned char>& salt);
    bool generateAndRegisterX3DHKeys(const QString& username, const std::vector<unsigned char>& kek, QString& errorMsg);

    enum RequestType {
        Challenge,
        Login
    } currentRequestType;
    // TODO: Add database connection or storage mechanism
};
