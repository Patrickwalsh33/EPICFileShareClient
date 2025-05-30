#include "registerManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../../key_management/X3DHKeys/OneTimeKeyPair.h"
#include "../../key_management/EncryptionKeyGenerator.h"
#include "../../key_management/KeyEncryptor.h"

RegisterManager::RegisterManager(QObject *parent) : QObject(parent),
networkManager(new QNetworkAccessManager(this)),
currentReply(nullptr)
{
    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system";
    }
}

RegisterManager::~RegisterManager()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void RegisterManager::setServerUrl(const QString &url) {
    serverUrl = url;
}

bool RegisterManager::sendRegistrationData(const QJsonObject& registrationData) {
    qDebug() << "Sending registration data to server";

    if (serverUrl.isEmpty()) {
        emit registrationFailed("Server URL is not set.");
        return false;
    }

    try {
        QJsonDocument jsonDoc(registrationData);
        QByteArray jsonData = jsonDoc.toJson();

        // Create network request
        QNetworkRequest request(QUrl(serverUrl + "/auth/register"));
        request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");

        // SSL configuration
        QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
        sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
        request.setSslConfiguration(sslConfig);

        // Send POST request
        currentReply = networkManager->post(request, jsonData);

        // Connect signals
        connect(currentReply, &QNetworkReply::finished,
                this, &RegisterManager::handleRegistrationFinished);
        connect(currentReply, &QNetworkReply::sslErrors,
                this, &RegisterManager::handleSslErrors);
        connect(currentReply, &QNetworkReply::errorOccurred,
                this, &RegisterManager::handleNetworkError);

        return true;

    } catch (const std::exception& e) {
        emit registrationFailed(QString("Failed to send registration data: %1").arg(e.what()));
        return false;
    }
}


void RegisterManager::handleRegistrationFinished()
{
    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray response = currentReply->readAll();
        qDebug() << "Registration successful. Server response:" << response;
        emit registrationSucceeded();
    } else {
        QString errorMsg = QString("Registration failed: %1").arg(currentReply->errorString());
        qDebug() << errorMsg;
        emit registrationFailed(errorMsg);
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void RegisterManager::handleSslErrors(const QList<QSslError> &errors) {
    qDebug() << "SSL errors detected, but ignoring for testing:";
    for (const QSslError &error : errors) {
        qDebug() << "  -" << error.errorString();
    }

    if (currentReply) {
        currentReply->ignoreSslErrors();
    }
}

void RegisterManager::handleNetworkError(QNetworkReply::NetworkError error)
{
    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred during registration:" << errorString;
    emit registrationFailed(errorString);
}