#include "receivedfilesmanager.h"
#include "../SessionManager/SessionManager.h"
#include <QDebug>
#include <QUrl>
#include <QNetworkRequest>
#include <QSslConfiguration>
#include <QJsonDocument>
#include <QJsonObject>

ReceivedFilesManager::ReceivedFilesManager(QObject *parent)
    : QObject(parent),
      networkManager(new QNetworkAccessManager(this)),
      currentReply(nullptr),
      serverUrl("") // Initialize serverUrl, can be set via setServerUrl
{
    // It's good practice to check for SSL support
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
    // networkManager is a child of this QObject, Qt should handle its deletion.
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
    // You might need to load CA certificates or set specific SSL protocols if default isn't enough
    // sslConfig.setPeerVerifyMode(QSslSocket::VerifyNone); // Use for testing only if cert issues
    request.setSslConfiguration(sslConfig);

    qDebug() << "Fetching unread messages from:" << inboxUrl.toString();

    currentReply = networkManager->get(request);

    connect(currentReply, &QNetworkReply::finished, this, &ReceivedFilesManager::handleInboxResponse);
    connect(currentReply, &QNetworkReply::sslErrors, this, &ReceivedFilesManager::handleSslErrors);
    // Use the new Qt5 signal syntax for errorOccurred if available and preferred
    // connect(currentReply, QOverload<QNetworkReply::NetworkError>::of(&QNetworkReply::errorOccurred), 
    //         this, &ReceivedFilesManager::handleNetworkError);
    // Fallback for broader compatibility or if QOverload is problematic in the env:
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
    // Depending on policy, you might ignore some errors for testing:
    // currentReply->ignoreSslErrors(); 
    // However, it's better to fix SSL issues on the server or client trust store.
    emit sslErrorsSignal(errorString); // Emit a general SSL error signal
    // Optionally also emit fetchMessagesFailed if SSL errors are critical
    if (currentReply && currentReply->error() != QNetworkReply::NoError) { // If an actual network error code is also set
         // emit fetchMessagesFailed("SSL Error occurred: " + errorString);
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
    
    // Avoid double signaling if 'finished' will also report an error.
    // The 'finished' signal is always emitted, even if an error occurred.
    // So, we let handleInboxResponse deal with emitting fetchMessagesFailed based on currentReply->error().
    // This slot is more for logging or specific reactions to network-level errors before 'finished'.
    // If currentReply is already scheduled for deletion or deleted by 'finished' handler, this might be too late.
    // It's safer to check currentReply->error() in the 'finished' slot primarily.
} 