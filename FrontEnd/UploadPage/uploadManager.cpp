#include "uploadManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>
#include <QUrlQuery>

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

    connect(currentReply, &QNetworkReply::finished,
            this, &uploadManager::handleUploadFinished);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &uploadManager::handleNetworkError);
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