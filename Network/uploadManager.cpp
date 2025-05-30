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

bool uploadManager::uploadFile(const QByteArray&fileData, const QByteArray &EncryptedDek) {

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
    request.setRawHeader("X-DEK", EncryptedDek.toBase64());
    request.setSslConfiguration(QSslConfiguration::defaultConfiguration());

    currentReply = networkManager->post(request, fileData);

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
void uploadManager::handleSslErrors(const QList<QSslError> &errors)
{
    QString errorString;
    for (const QSslError &error : errors) {
        errorString += error.errorString() + "\n";
    }
    emit sslError(errorString);
}

void uploadManager::handleNetworkError(QNetworkReply::NetworkError error)
{
    QString errorString = currentReply->errorString();
    qDebug() << "Network error occurred:" << errorString;
    emit uploadFailed(errorString);
}