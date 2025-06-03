#include "uploadManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QUrlQuery>
#include <QHttpMultiPart>
#include <QHttpPart>

#include "../SessionManager/SessionManager.h"


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

bool uploadManager::requestRecipientKeys(const QString &username)
{
    qDebug() << "Requesting keys for recipient:" << username;

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    QString recipientUsername = username;



    qDebug() << "JWT Token length:" << jwtToken.length();
    qDebug() << "JWT Token (first 50 chars):" << jwtToken.left(50);
    qDebug() << "JWT Token is empty:" << jwtToken.isEmpty();


    if (username.isEmpty()) {
        emit recipientKeysFailed("Username cannot be empty.");
        return false;
    }
    setServerUrl("https://leftovers.gobbler.info");
    qDebug() << "Requesting pre key bundle for:" << recipientUsername;


    if (serverUrl.isEmpty()) {
        emit recipientKeysFailed("Server URL is not set.");
        return false;
    }

    // Create URL with username parameter
    QUrl url(serverUrl + "/users/");
    QUrlQuery query;
    query.addQueryItem("username", recipientUsername);
    url.setQuery(query);

    // Create network request
    QNetworkRequest request(url);
    request.setRawHeader("Authorization", ("Bearer " + jwtToken));
    qDebug() << "Network request:" << request.url();

    // SSL configuration
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    // Send GET request
    currentRequestType = RetrieveKeys;
    currentReply = networkManager->get(request);
    qDebug() << "Key Retrieval Sent for:" << recipientUsername;

    connect(currentReply, &QNetworkReply::finished, this , &uploadManager::handleKeysReceived);
    connect(currentReply, &QNetworkReply::sslErrors, this , &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred, this, &uploadManager::handleNetworkError);
    

    return true;
}

bool uploadManager::uploadFile(const QByteArray &encryptedData, const QString &file_uuid, const QString &originalFileName) {
    qDebug() << "Attempting to upload file. UUID:" << file_uuid << "Original Filename:" << originalFileName;

    if (encryptedData.isEmpty()) {
        emit uploadFailed("Encrypted file data is empty.");
        return false;
    }
    if (file_uuid.isEmpty()) {
        emit uploadFailed("File UUID is empty.");
        return false;
    }
    if (originalFileName.isEmpty()) {
        emit uploadFailed("Original filename is empty (needed for multipart form).");
        return false;
    }

    // Ensure serverUrl is set appropriately, e.g., to "https://leftovers.gobbler.info"
    // The specific endpoint is /upload_data
    if (serverUrl.isEmpty()) {
        // Attempt to set a default or fetch from a config if appropriate
        // For now, let's assume it was set earlier via setServerUrl or hardcode for this specific function if necessary
        // If this service only uploads to one place, hardcoding here might be acceptable short-term.
        // Example: setServerUrl("https://leftovers.gobbler.info");
        qWarning() << "Server URL is not set in uploadManager. Attempting to use default or last set.";
        if (serverUrl.isEmpty()) { // Check again if it wasn't set by a potential default mechanism
             emit uploadFailed("Server URL for upload is not set.");
             return false;
        }
    }

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        emit uploadFailed("JWT Token is missing. Cannot authenticate.");
        return false;
    }

    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);

    // Part 1: file_uuid
    QHttpPart uuidPart;
    uuidPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file_uuid\""));
    uuidPart.setBody(file_uuid.toUtf8());
    multiPart->append(uuidPart);

    // Part 2: encrypted_file
    QHttpPart filePart;
    // The Content-Type for the file part can be generic like application/octet-stream
    // or more specific if the server expects/uses it.
    filePart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("application/octet-stream"));
    QString contentDisposition = QString("form-data; name=\"encrypted_file\"; filename=\"%1\"").arg(originalFileName);
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant(contentDisposition));
    filePart.setBody(encryptedData);
    multiPart->append(filePart);

    QUrl uploadUrl(serverUrl + "/upload_data");
    QNetworkRequest request(uploadUrl);
    request.setRawHeader("Authorization", "Bearer " + jwtToken);
    // QSslConfiguration can be set here if needed, similar to other requests
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    qDebug() << "Uploading to URL:" << uploadUrl.toString();
    currentReply = networkManager->post(request, multiPart);
    multiPart->setParent(currentReply); // Important for memory management: QHttpMultiPart will be deleted when QNetworkReply is deleted.

    currentRequestType = SendFile; // Assuming you have this enum member to track request type

    connect(currentReply, &QNetworkReply::finished, this, &uploadManager::handleUploadFinished);
    // connect(currentReply, &QNetworkReply::uploadProgress, this, &uploadManager::uploadProgress); // If you want to emit progress
    connect(currentReply, &QNetworkReply::sslErrors, this, &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred, this, &uploadManager::handleNetworkError);

    return true;
}

void uploadManager::handleKeysReceived()
{
    if (!currentReply) {
        qWarning() << "handleKeysReceived called with null currentReply";
        return;
    }

    if (currentReply->error() == QNetworkReply::NoError) {
        QByteArray responseData = currentReply->readAll();
        qDebug() << "Keys received:" << responseData;
        qDebug() << "Recipient keys received successfully. Size:" << responseData.size();

        emit recipientKeysReceived(responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Failed to retrieve recipient keys. Error:" << errorMsg;
        emit recipientKeysFailed(errorMsg);
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}


void uploadManager::handleUploadFinished()
{
    if (!currentReply) {
        qWarning() << "handleUploadFinished called with null currentReply";
        return;
    }

    QByteArray responseData = currentReply->readAll();

    if (currentReply->error() == QNetworkReply::NoError) {
        qDebug() << "Upload successful. Server response:" << responseData;
        emit uploadSucceeded(responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Upload failed. Error:" << errorMsg << "Server response:" << responseData;
        emit uploadFailed(errorMsg + " (Server response: " + QString::fromUtf8(responseData) + ")");
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