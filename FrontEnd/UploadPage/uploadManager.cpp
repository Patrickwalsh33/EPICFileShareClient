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
#include <QJsonObject>
#include <QJsonDocument>

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

bool uploadManager::uploadFile(const QByteArray &encryptedData, 
                               const QString &file_uuid, 
                               const QString &originalFileName,
                               const QString &recipientUsername,
                               const QByteArray &ephemeralPublicKey,
                               const QByteArray &encryptedFileMetadata,
                               const QByteArray &metadataNonce) {
    qDebug() << "Step 1 (uploadFile): Initiating file data upload. UUID:" << file_uuid << "Recipient:" << recipientUsername;

    if (encryptedData.isEmpty()) {
        emit uploadFailed("File data upload failed: Encrypted file data is empty.");
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

    // Store metadata for the second request
    this->m_recipientUsername_temp = recipientUsername;
    this->m_ephemeralPublicKey_temp = ephemeralPublicKey;
    this->m_encryptedFileMetadata_temp = encryptedFileMetadata;
    this->m_metadataNonce_temp = metadataNonce;

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        emit uploadFailed("File data upload failed: JWT Token is missing.");
        return false;
    }
    if (serverUrl.isEmpty()) {
        emit uploadFailed("File data upload failed: Server URL is not set.");
        return false;
    }

    // --- First POST request: Upload encrypted file data ---
    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QHttpPart uuidPart;
    uuidPart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant("form-data; name=\"file_uuid\""));
    uuidPart.setBody(file_uuid.toUtf8());
    multiPart->append(uuidPart);

    QHttpPart filePart;
    filePart.setHeader(QNetworkRequest::ContentTypeHeader, QVariant("application/octet-stream"));
    QString contentDisposition = QString("form-data; name=\"encrypted_file\"; filename=\"%1\"").arg(originalFileName);
    filePart.setHeader(QNetworkRequest::ContentDispositionHeader, QVariant(contentDisposition));
    filePart.setBody(encryptedData);
    multiPart->append(filePart);

    QUrl uploadDataUrl(serverUrl + "/upload_data");
    QNetworkRequest request_upload_data(uploadDataUrl);
    request_upload_data.setRawHeader("Authorization", "Bearer " + jwtToken);
    QSslConfiguration sslConfig_upload_data = QSslConfiguration::defaultConfiguration(); // Renamed for clarity
    request_upload_data.setSslConfiguration(sslConfig_upload_data);

    qDebug() << "Uploading file data to URL:" << uploadDataUrl.toString();
    currentRequestType = SendFile;
    currentReply = networkManager->post(request_upload_data, multiPart);
    multiPart->setParent(currentReply); 

    connect(currentReply, &QNetworkReply::finished, this, &uploadManager::handleUploadFinished);
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


void uploadManager::handleUploadFinished() // Handles reply from /upload_data (file content)
{
    if (!currentReply) {
        qWarning() << "handleUploadFinished called with null currentReply";
        // This case should ideally not happen if signal/slot connections are correct
        emit uploadFailed("Internal error: File upload reply is null.");
        return;
    }

    QByteArray responseData_fileUpload = currentReply->readAll();
    QNetworkReply::NetworkError error_fileUpload = currentReply->error();
    QString errorString_fileUpload = currentReply->errorString();
    
    // Clean up the first reply before making a new request or emitting final failure
    currentReply->deleteLater();
    currentReply = nullptr;

    if (error_fileUpload != QNetworkReply::NoError) {
        qCritical() << "Step 1 Failed (File Data Upload). Error:" << errorString_fileUpload << "Server response:" << responseData_fileUpload;
        emit uploadFailed("File data upload failed: " + errorString_fileUpload + " (Server response: " + QString::fromUtf8(responseData_fileUpload) + ")");
        return;
    }

    qDebug() << "Step 1 Success (File Data Upload). Server response:" << responseData_fileUpload;
    qDebug() << "Step 2 (handleUploadFinished): Initiating metadata share.";

    // --- Second POST request: Share file metadata ---
    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken(); // Get token again, in case it expired or for atomicity
    if (jwtToken.isEmpty()) {
        emit uploadFailed("Metadata share failed: JWT Token is missing for second request.");
        return;
    }
     if (serverUrl.isEmpty()) { // Should still be set from the first part
        emit uploadFailed("Metadata share failed: Server URL is not set for second request.");
        return;
    }

    QJsonObject metadataJsonPayload;
    metadataJsonPayload["recipient_username"] = this->m_recipientUsername_temp;
    metadataJsonPayload["ephemeral_key"] = QString::fromLatin1(this->m_ephemeralPublicKey_temp.toBase64());
    metadataJsonPayload["encrypted_file_metadata"] = QString::fromLatin1(this->m_encryptedFileMetadata_temp.toBase64());
    metadataJsonPayload["encrypted_metadata_nonce"] = QString::fromLatin1(this->m_metadataNonce_temp.toBase64());

    QJsonDocument jsonDoc(metadataJsonPayload);
    QByteArray jsonDataForShare = jsonDoc.toJson(QJsonDocument::Compact);

    QUrl shareMetadataUrl(serverUrl + "/files/share");
    QNetworkRequest request_share_metadata(shareMetadataUrl);
    request_share_metadata.setRawHeader("Authorization", "Bearer " + jwtToken);
    request_share_metadata.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    QSslConfiguration sslConfig_share_metadata = QSslConfiguration::defaultConfiguration(); // Renamed for clarity
    request_share_metadata.setSslConfiguration(sslConfig_share_metadata);

    qDebug() << "Sharing metadata to URL:" << shareMetadataUrl.toString() << "Payload:" << jsonDataForShare;
    currentRequestType = ShareMetadata;
    currentReply = networkManager->post(request_share_metadata, jsonDataForShare);

    connect(currentReply, &QNetworkReply::finished, this, &uploadManager::handleMetadataShareFinished);
    connect(currentReply, &QNetworkReply::sslErrors, this, &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred, this, &uploadManager::handleNetworkError);
}

void uploadManager::handleMetadataShareFinished() // Handles reply from /files/share
{
    if (!currentReply) {
        qWarning() << "handleMetadataShareFinished called with null currentReply";
        emit uploadFailed("Internal error: Metadata share reply is null.");
        return;
    }

    QByteArray responseData_metadataShare = currentReply->readAll();
    QNetworkReply::NetworkError error_metadataShare = currentReply->error();
    QString errorString_metadataShare = currentReply->errorString();

    if (error_metadataShare == QNetworkReply::NoError) {
        qDebug() << "Step 2 Success (Metadata Share). Server response:" << responseData_metadataShare;
        emit uploadSucceeded(responseData_metadataShare); // This is the final success signal
    } else {
        qCritical() << "Step 2 Failed (Metadata Share). Error:" << errorString_metadataShare << "Server response:" << responseData_metadataShare;
        emit uploadFailed("File metadata share failed: " + errorString_metadataShare + " (Server response: " + QString::fromUtf8(responseData_metadataShare) + ")");
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