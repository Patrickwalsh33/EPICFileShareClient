
#include "loginManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <QUrlQuery>

LoginManager::LoginManager(QObject *parent) : QObject(parent),
networkManager(new QNetworkAccessManager(this)),
currentReply(nullptr),
currentRequestType(Challenge)
{
    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system";
    }
}

LoginManager::~LoginManager()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void LoginManager::setServerUrl(const QString &url) {
    serverUrl = url;
}

bool LoginManager::requestChallenge(const QString &username) {
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
            this, &LoginManager::handleChallengeResponse);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &LoginManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &LoginManager::handleNetworkError);

    return true;
}

bool LoginManager::submitLogin(const QString &username, const QByteArray &signature, const QByteArray &nonce) {
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
            this, &LoginManager::handleLoginResponse);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &LoginManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &LoginManager::handleNetworkError);

    return true;
}

void LoginManager::handleChallengeResponse()
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
                QByteArray nonce = QByteArray::fromBase64(nonceBase64.toLatin1());
                qDebug() << "Received nonce (Base64):" << nonceBase64;
                emit challengeReceived(nonce);
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

void LoginManager::handleLoginResponse()
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

void LoginManager::handleSslErrors(const QList<QSslError> &errors) {
    qDebug() << "SSL errors detected, but ignoring for testing:";
    for (const QSslError &error : errors) {
        qDebug() << "  -" << error.errorString();
    }

    if (currentReply) {
        currentReply->ignoreSslErrors();
    }
}

void LoginManager::handleNetworkError(QNetworkReply::NetworkError error)
{
    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred during" << (currentRequestType == Challenge ? "challenge" : "login") << ":" << errorString;

    if (currentRequestType == Challenge) {
        emit challengeFailed(errorString);
    } else {
        emit loginFailed(errorString);
    }
}