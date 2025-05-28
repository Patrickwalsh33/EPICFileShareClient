//
// Created by Andrew Jaffray on 26/05/2025.
//

#include "uploadManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>


uploadManager::uploadManager(QObject *parent) : QObject(parent),
   networkManager(new QNetworkAccessManager(this)),
   currentReply(nullptr)
{
    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system";
    }
}
uploadManager::~uploadManager()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void uploadManager::setServerUrl(const QString &url) {
    serverUrl = url;
}

bool uploadManager::uploadFile(const QByteArray&fileData, const QByteArray &EncryptedDek, const QString &fileName, const QString &mimeType, const QByteArray &ephemeralKey, const QString &uuid, const QByteArray &oneTimePreKey) {

    qDebug() << "Uploading file.";
    if (fileData.isEmpty()) {
        emit uploadFailed("File data is empty.");
        return false;
    }

    if (serverUrl.isEmpty()) {
        emit uploadFailed("Server URL is not set.");
        return false;
    }
    currentDek = EncryptedDek;

    QNetworkRequest request{QUrl(serverUrl)}; // creates a QNetworkRequest object that will be used to make a HTTPS request
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/octet-stream"); //tells the server that we are sending binary data
    request.setRawHeader("X-DEK", EncryptedDek.toBase64());             // adds a custom header "X-DEK" containing the encrypted Data Encryption Key (DEK)
    request.setRawHeader("X-Filename", fileName.toUtf8().toBase64());   // adds the original filename as a Base64-encoded header.
    request.setRawHeader("X-Mime-Type", mimeType.toUtf8());             // adds the MIME type of the file as a header
    request.setRawHeader("X-Ephemeral-Key", ephemeralKey.toBase64());   // adds the ephemeral key as a Base64-encoded header
    request.setRawHeader("X-UUID", uuid.toUtf8());                      // adds a unique identifier for the upload as a header
    request.setRawHeader("X-OTP-Key", oneTimePreKey.toBase64());        // adds the one-time pre-key as a Base64-encoded header
      // sets the SSL configuration for the request to use the default configuration

    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    request.setSslConfiguration(sslConfig);

    currentReply = networkManager->post(request, fileData); //this sends the POST request to the server with the file data as the body of the request

    connect(currentReply, &QNetworkReply::uploadProgress,
            this, &uploadManager::handleUploadProgress);
    connect(currentReply, &QNetworkReply::finished,
            this, &uploadManager::handleUploadFinished);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &uploadManager::handleNetworkError);
    return true;
}

void uploadManager::handleUploadProgress(qint64 bytesSent, qint64 bytesTotal)
{
    emit uploadProgress(bytesSent, bytesTotal);
}

void uploadManager::handleUploadFinished()
{
    if (currentReply->error() == QNetworkReply::NoError) {
        emit uploadSucceeded(currentDek);
    } else {
        emit uploadFailed(currentReply->errorString());
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}
void uploadManager::handleSslErrors(const QList<QSslError> &errors) {
    qDebug() << "SSL errors detected, but ignoring for testing:";
    for (const QSslError &error: errors) {
        qDebug() << "  -" << error.errorString();
    }

    if (currentReply) {
        currentReply->ignoreSslErrors();
    }
}



void uploadManager::handleNetworkError(QNetworkReply::NetworkError error)
{
    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred:" << errorString;
    emit uploadFailed(errorString);
}