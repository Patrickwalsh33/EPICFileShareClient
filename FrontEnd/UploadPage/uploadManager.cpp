#include "uploadManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>


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

bool uploadManager::uploadFile(const QByteArray&fileData, const QByteArray &EncryptedDek, const QUuid &uuid, const QString &jwtToken) {

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
    request.setRawHeader("X-File-UUID", uuid.toByteArray());
    request.setRawHeader("Authorization", "Bearer " + jwtToken.toUtf8());
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

bool uploadManager::requestRecipientKeys(const QString &username) {
    qDebug() << "Requesting keys for recipient:" << username;

    if (username.isEmpty()) {
        emit recipientKeysFailed("Username cannot be empty.");
        return false;
    }

    if (serverUrl.isEmpty()) {
        emit recipientKeysFailed("Server URL is not set.");
        return false;
    }

    QUrl url(serverUrl + "/upload/user"); //TODO: change this to the right endpoint
    QUrlQuery query;
    query.addQueryItem("username", username);
    url.setQuery(query);

    qDebug() << "Challenge URL:" << url.toString();

    // Create network request
    QNetworkRequest request(url);
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    //sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone);
    request.setSslConfiguration(sslConfig);

    currentRequestType = KeyRetrieval;
    currentReply = networkManager->get(request);

    connect(currentReply, &QNetworkReply::finished,
            this, &uploadManager::handleKeyRetrievalFinished);
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
    if (currentRequestType == Upload) {
        if (currentReply->error() == QNetworkReply::NoError) {
            emit uploadSucceeded(currentDek);
        } else {
            emit uploadFailed(currentReply->errorString());
        }
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void uploadManager::handleKeyRetrievalFinished() {
    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray response = currentReply->readAll();
        qDebug() << "Key retrieval response received:" << response;

        QJsonDocument jsonDoc = QJsonDocument::fromJson(response);
        if (jsonDoc.isObject()) {
            QJsonObject jsonObj = jsonDoc.object();

            if (jsonObj.contains("username") &&
                jsonObj.contains("identityPublicKey") &&
                jsonObj.contains("signedPreKeyPublicKey") &&
                jsonObj.contains("signedPreKeySignature") &&
                jsonObj.contains("oneTimeKeys")) {

                QString username = jsonObj["username"].toString();

                //decodes all the keys from base64
                QByteArray identityPublicKey = QByteArray::fromBase64(
                        jsonObj["identityPublicKey"].toString().toLatin1());
                QByteArray signedPreKeyPublicKey = QByteArray::fromBase64(
                        jsonObj["signedPreKeyPublicKey"].toString().toLatin1());
                QByteArray signedPreKeySignature = QByteArray::fromBase64(
                        jsonObj["signedPreKeySignature"].toString().toLatin1());

                //extracts the one-time keys from the array
                QList<QByteArray> oneTimeKeys;
                QJsonArray oneTimeKeysArray = jsonObj["oneTimeKeys"].toArray();
                for (const QJsonValue &keyValue : oneTimeKeysArray) {
                    QByteArray oneTimeKey = QByteArray::fromBase64(
                            keyValue.toString().toLatin1());
                    oneTimeKeys.append(oneTimeKey);
                }
                qDebug() << "Successfully retrieved keys for user:" << username;
                qDebug() << "Number of one-time keys:" << oneTimeKeys.size();

                emit recipientKeysReceived(username, identityPublicKey,
                                           signedPreKeyPublicKey, signedPreKeySignature,
                                           oneTimeKeys);
            } else {
                emit recipientKeysFailed("Invalid response: missing required fields");
            }
    } else {
            emit recipientKeysFailed("Invalid JSON response");
        }
} else {
        QString errorMsg = QString("Key retrieval failed: %1").arg(currentReply->errorString());
        qDebug() << errorMsg;
        emit recipientKeysFailed(errorMsg);
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
    qDebug() << "Network error occurred during" << (currentRequestType == Upload ? "upload" : "key retrieval") <<":" << errorString;
    if (currentRequestType == Upload) {
        emit uploadFailed(errorString);
    } else {
        emit recipientKeysFailed(errorString);
    }
}