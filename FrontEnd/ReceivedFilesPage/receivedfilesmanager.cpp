#include "receivedfilesmanager.h"
#include "../SessionManager/SessionManager.h"
#include <QDebug>
#include <QUrl>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>

ReceivedFilesManager::ReceivedFilesManager(QObject *parent)
    : QObject(parent),
      networkManager(new QNetworkAccessManager(this)),
      currentReply(nullptr),
      serverUrl("") // Initialize serverUrl, can be set via setServerUrl
{

    if (!QSslSocket::supportsSsl()) {
        qWarning() << "SSL is not supported on this system!";
    }
}

ReceivedFilesManager::~ReceivedFilesManager()
{
    if (currentReply) {
        currentReply->abort(); // Abort if a request is in progress
        currentReply->deleteLater();
    }

}

void ReceivedFilesManager::setServerUrl(const QString &url)
{
    this->serverUrl = url;
}

void ReceivedFilesManager::fetchUnreadMessages()
{
    if (serverUrl.isEmpty()) {
        qWarning() << "Server URL is not set in ReceivedFilesManager.";
        emit fetchMessagesFailed("Server URL not configured.");
        return;
    }

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        qWarning() << "JWT Token is missing. Cannot fetch messages.";
        emit fetchMessagesFailed("Authentication token not found. Please log in again.");
        return;
    }

    // If a request is already running, disconnect its signals and abort it.
    if (currentReply && currentReply->isRunning()) {
        qWarning() << "Fetch unread messages request already in progress. Disconnecting and aborting previous.";
        // Disconnect all signals from the old reply to prevent it from calling slots
        disconnect(currentReply, nullptr, nullptr, nullptr);
        currentReply->abort();
        currentReply->deleteLater(); // Schedule for deletion
        currentReply = nullptr; 
    }

    QUrl inboxUrl(serverUrl + "/messages/inbox");
    QNetworkRequest request(inboxUrl);
    request.setRawHeader("Authorization", "Bearer " + jwtToken);

    // Setup SSL configuration (important for HTTPS)
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();

    request.setSslConfiguration(sslConfig);

    qDebug() << "Fetching unread messages from:" << inboxUrl.toString();

    currentReply = networkManager->get(request);

    connect(currentReply, &QNetworkReply::finished, this, &ReceivedFilesManager::handleInboxResponse);
    connect(currentReply, &QNetworkReply::sslErrors, this, &ReceivedFilesManager::handleSslErrors);

    connect(currentReply, SIGNAL(errorOccurred(QNetworkReply::NetworkError)), 
            this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));
}

void ReceivedFilesManager::handleInboxResponse()
{
    if (!currentReply) {
        qWarning() << "handleInboxResponse called with no currentReply (or reply already handled).";
        return;
    }

    QNetworkReply::NetworkError error = currentReply->error();
    QByteArray responseData = currentReply->readAll(); // Read data regardless of error type

    if (error == QNetworkReply::OperationCanceledError) {
        qDebug() << "Previous message fetch operation was canceled. No action taken.";
        // Don't emit any success/failure signals for a deliberately aborted request.
    } else if (error == QNetworkReply::NoError) {
        qDebug() << "Successfully fetched messages. Size:" << responseData.size();
        qDebug() << "Response:" << responseData.left(500); 
        emit unreadMessagesReceived(responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Failed to fetch messages. Error:" << errorMsg;
        qCritical() << "Server Response (if any):" << responseData;
        emit fetchMessagesFailed(errorMsg + " Server details: " + QString::fromUtf8(responseData)); // Ensure responseData is properly converted
    }

    currentReply->deleteLater();
    currentReply = nullptr;
}

void ReceivedFilesManager::handleSslErrors(const QList<QSslError> &errors)
{
    QString errorString;
    for (const QSslError &error : errors) {
        qDebug() << "SSL Error:" << error.errorString();
        errorString += error.errorString() + "\n";
    }

    emit sslErrorsSignal(errorString); // Emit a general SSL error signal

    if (currentReply && currentReply->error() != QNetworkReply::NoError) {
    } else if (!errors.isEmpty()){
        emit fetchMessagesFailed("SSL Error occurred: " + errors.first().errorString());
    }
}

void ReceivedFilesManager::handleNetworkError(QNetworkReply::NetworkError errorCode)
{
    if (!currentReply) {
        qWarning() << "handleNetworkError called with no currentReply or after it was handled.";
        return;
    }
    QString errorString = currentReply->errorString(); // Get error string from the reply
    qCritical() << "Network error occurred:" << errorCode << "-" << errorString;

}

// New method to request sender's public keys (pre-key bundle)
bool ReceivedFilesManager::requestSenderKeys(const QString &username)
{
    qDebug() << "Requesting sender keys for user:" << username;

    if (serverUrl.isEmpty()) {
        qWarning() << "Server URL is not set in ReceivedFilesManager for sender key request.";
        emit fetchSenderKeysFailed("Server URL not configured for sender key request.");
        return false;
    }

    QByteArray jwtToken = SessionManager::getInstance()->getAccessToken();
    if (jwtToken.isEmpty()) {
        qWarning() << "JWT Token is missing. Cannot fetch sender keys.";
        emit fetchSenderKeysFailed("Authentication token not found. Please log in again.");
        return false;
    }

    if (username.isEmpty()) {
        emit fetchSenderKeysFailed("Username for sender key request cannot be empty.");
        return false;
    }

    // If a request is already running, disconnect its signals and abort it.
    if (currentReply && currentReply->isRunning()) {
        qWarning() << "Sender key request already in progress. Disconnecting and aborting previous.";
        disconnect(currentReply, nullptr, nullptr, nullptr);
        currentReply->abort();
        currentReply->deleteLater();
        currentReply = nullptr;
    }

    QUrl userKeysUrl(serverUrl + "/users/"); // Same endpoint as in uploadManager
    QUrlQuery query;
    query.addQueryItem("username", username);
    userKeysUrl.setQuery(query);

    QNetworkRequest request(userKeysUrl);
    request.setRawHeader("Authorization", "Bearer " + jwtToken);
    QSslConfiguration sslConfig = QSslConfiguration::defaultConfiguration();
    request.setSslConfiguration(sslConfig);

    qDebug() << "Fetching sender keys from:" << userKeysUrl.toString();
    currentRequestType = RetrieveSenderKeys;
    currentReply = networkManager->get(request);

    connect(currentReply, &QNetworkReply::finished, this, &ReceivedFilesManager::handleSenderKeysResponse);
    connect(currentReply, &QNetworkReply::sslErrors, this, &ReceivedFilesManager::handleSslErrors);
    connect(currentReply, SIGNAL(errorOccurred(QNetworkReply::NetworkError)), 
            this, SLOT(handleNetworkError(QNetworkReply::NetworkError)));

    return true;
}

// New slot to handle the response for sender key request
void ReceivedFilesManager::handleSenderKeysResponse()
{
    if (!currentReply) {
        qWarning() << "handleSenderKeysResponse called with no currentReply (or reply already handled).";
        return;
    }

    QNetworkReply::NetworkError error = currentReply->error();
    QByteArray responseData = currentReply->readAll();

    if (error == QNetworkReply::OperationCanceledError) {
        qDebug() << "Sender key fetch operation was canceled. No action taken.";
    } else if (error == QNetworkReply::NoError) {
        qDebug() << "Successfully fetched sender keys. Size:" << responseData.size();
        qDebug() << "Response:" << responseData.left(500);
        emit senderKeysReceived(responseData);
    } else {
        QString errorMsg = currentReply->errorString();
        qCritical() << "Failed to fetch sender keys. Error:" << errorMsg;
        qCritical() << "Server Response (if any):" << responseData;
        emit fetchSenderKeysFailed(errorMsg + " Server details: " + QString::fromUtf8(responseData));
    }

    currentReply->deleteLater();
    currentReply = nullptr;
} 