#include "sentfilesmanager.h"
#include "../SessionManager/SessionManager.h" // For JWT token
#include <QDebug>
#include <QUrl>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray> // For parsing the list of UUIDs

SentFilesManager::SentFilesManager(QObject *parent)
    : QObject(parent),
      networkManager(new QNetworkAccessManager(this)),
      currentReply(nullptr),
      serverUrl(""),
      currentRequestType(FetchOwnedUUIDs) // Default
{
    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system!";
    }
}

SentFilesManager::~SentFilesManager()
{
    if (currentReply) {
        currentReply->abort();
        currentReply->deleteLater();
    }
}

void SentFilesManager::setServerUrl(const QString &url)
{
    this->serverUrl = url;
}

void SentFilesManager::fetchOwnedFileUuids()
{
    if (serverUrl.isEmpty()) {
        qWarning() << "Server URL is not set in SentFilesManager.";
        emit fetchOwnedFileUuidsFailed("Server URL not configured.");
        return;
    }

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        qWarning() << "JWT Token is missing. Cannot fetch owned file UUIDs.";
        emit fetchOwnedFileUuidsFailed("Authentication token not found. Please log in again.");
        return;
    }

    if (currentReply && currentReply->isRunning()) {
        qWarning() << "Request already in progress. Disconnecting and aborting previous.";
        disconnect(currentReply, nullptr, nullptr, nullptr);
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }

    QUrl ownedUuidsUrl(serverUrl + "/files/owned_uuids");
    QNetworkRequest request(ownedUuidsUrl);
    request.setRawHeader("Authorization", "Bearer " + jwtToken);

    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    qDebug() << "Fetching owned file UUIDs from:" << ownedUuidsUrl.toString();
    currentRequestType = FetchOwnedUUIDs;
    currentReply = networkManager->get(request);

    connect(currentReply, &QNetworkReply::finished, this, &SentFilesManager::handleOwnedFileUuidsResponse);
    connect(currentReply, &QNetworkReply::sslErrors, this, &SentFilesManager::handleSslErrors);
    connect(currentReply, SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
            this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));
}

void SentFilesManager::deleteFile(const QString &file_uuid)
{
    if (serverUrl.isEmpty()) {
        qWarning() << "Server URL is not set for file deletion.";
        emit fileDeleteFailed(file_uuid, "Server URL not configured.");
        return;
    }

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        qWarning() << "JWT Token is missing. Cannot delete file.";
        emit fileDeleteFailed(file_uuid, "Authentication token not found.");
        return;
    }

    if (file_uuid.isEmpty()) {
        emit fileDeleteFailed(file_uuid, "File UUID for deletion cannot be empty.");
        return;
    }

    if (currentReply && currentReply->isRunning()) {
        qWarning() << "Another request is already in progress. Aborting previous.";
        disconnect(currentReply, nullptr, nullptr, nullptr);
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }
    
    this->m_currentlyProcessedFileUuid = file_uuid;
    QUrl deleteUrl(serverUrl + "/files/" + file_uuid);
    QNetworkRequest request(deleteUrl);
    request.setRawHeader("Authorization", "Bearer " + jwtToken);

    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    qDebug() << "Attempting to delete file:" << deleteUrl.toString();
    currentRequestType = DeleteFile;
    currentReply = networkManager->deleteResource(request);

    connect(currentReply, &QNetworkReply::finished, this, &SentFilesManager::handleFileDeleteResponse);
    connect(currentReply, &QNetworkReply::sslErrors, this, &SentFilesManager::handleSslErrors);
    connect(currentReply, SIGNAL(errorOccurred(QNetworkReply::NetworkError)),
            this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));
}

void SentFilesManager::handleOwnedFileUuidsResponse()
{
    if (!currentReply || currentRequestType != FetchOwnedUUIDs) {
        qWarning() << "handleOwnedFileUuidsResponse called inappropriately or with no currentReply.";
        return;
    }

    QNetworkReply::NetworkError error = currentReply->error();
    QByteArray responseData = currentReply->readAll();

    if (error == QNetworkReply::OperationCanceledError) {
        qDebug() << "Owned file UUIDs fetch operation was canceled.";
    } else if (error == QNetworkReply::NoError) {
        qDebug() << "Successfully fetched owned file UUIDs. Size:" << responseData.size();
        qDebug() << "Response:" << responseData.left(500);

        emit ownedFileUuidsReceived(responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Failed to fetch owned file UUIDs. Error:" << errorMsg;
        qCritical() << "Server Response (if any):" << responseData;
        emit fetchOwnedFileUuidsFailed(errorMsg + " Server details: " + QString::fromUtf8(responseData));
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void SentFilesManager::handleFileDeleteResponse()
{
    if (!currentReply || currentRequestType != DeleteFile) {
        qWarning() << "handleFileDeleteResponse called inappropriately or with no currentReply.";
        if (!m_currentlyProcessedFileUuid.isEmpty()) { // If we know which UUID it was, emit failure
            emit fileDeleteFailed(m_currentlyProcessedFileUuid, "Internal error: Delete response handled incorrectly.");
        }
        return;
    }

    QString processingUuid = m_currentlyProcessedFileUuid; // Copy before clearing
    m_currentlyProcessedFileUuid.clear(); 

    QNetworkReply::NetworkError error = currentReply->error();
    QByteArray responseData = currentReply->readAll();

    if (error == QNetworkReply::OperationCanceledError) {
        qDebug() << "File delete operation was canceled for UUID:" << processingUuid;

    } else if (error == QNetworkReply::NoError) {
        qDebug() << "Successfully processed delete request for UUID:" << processingUuid << ". Response:" << responseData;

        emit fileDeleteSucceeded(processingUuid, responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Failed to delete file for UUID:" << processingUuid << ". Error:" << errorMsg;
        qCritical() << "Server Response (if any):" << responseData;
        emit fileDeleteFailed(processingUuid, errorMsg + " Server details: " + QString::fromUtf8(responseData));
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void SentFilesManager::handleSslErrors(const QList<QSslError> &errors)
{
    if (!currentReply) return;

    QString errorString;
    for (const QSslError &error : errors) {
        qDebug() << "SSL Error:" << error.errorString();
        errorString += error.errorString() + "\n";
    }
    emit sslErrorsSignal(errorString); // General SSL error signal

    QString detailedError = "SSL Error occurred: " + (errors.isEmpty() ? "Unknown SSL Error" : errors.first().errorString());

    if (currentRequestType == FetchOwnedUUIDs) {
        emit fetchOwnedFileUuidsFailed(detailedError);
    } else if (currentRequestType == DeleteFile) {
        emit fileDeleteFailed(m_currentlyProcessedFileUuid, detailedError);
    }
    

}

void SentFilesManager::handleNetworkError(QNetworkReply::NetworkError errorCode)
{
    if (!currentReply || errorCode == QNetworkReply::OperationCanceledError) {

        return;
    }

    QString errorString = currentReply->errorString();
    qCritical() << "Network error occurred:" << errorCode << "-" << errorString;

    if (currentReply->error() == QNetworkReply::NoError) { // Error not caught by 'finished' handler yet
        if (currentRequestType == FetchOwnedUUIDs) {
            emit fetchOwnedFileUuidsFailed("Network Error: " + errorString);
        } else if (currentRequestType == DeleteFile) {
            emit fileDeleteFailed(m_currentlyProcessedFileUuid, "Network Error: " + errorString);

        }
    }

} 