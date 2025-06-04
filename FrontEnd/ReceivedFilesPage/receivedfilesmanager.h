#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>

class ReceivedFilesManager : public QObject
{
    Q_OBJECT

public:
    explicit ReceivedFilesManager(QObject *parent = nullptr);
    ~ReceivedFilesManager();

    void fetchUnreadMessages();
    void setServerUrl(const QString &url);
    bool requestSenderKeys(const QString &username);
    bool downloadEncryptedFile(const QString &file_uuid);

signals:
    void unreadMessagesReceived(const QByteArray &serverResponse);
    void fetchMessagesFailed(const QString &error);
    void sslErrorsSignal(const QString &error); // Renamed to avoid conflict if class is used elsewhere
    void senderKeysReceived(const QByteArray &serverResponse);
    void fetchSenderKeysFailed(const QString &error);
    void fileDownloadSucceeded(const QByteArray &encryptedFileBytes, const QString &file_uuid_ref);
    void fileDownloadFailed(const QString &error, const QString &file_uuid_ref);

private slots:
    void handleInboxResponse();
    void handleSenderKeysResponse();
    void handleFileDownloadResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError errorCode);

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    QString serverUrl;

    enum RequestType_ {
        RetrieveInboxMessages,
        RetrieveSenderKeys,
        DownloadEncryptedContent
    };
    RequestType_ currentRequestType;

    QByteArray m_encryptedFileMetadata_temp;
    QByteArray m_metadataNonce_temp;
    QString m_currentDownloadFileUuid_temp;
}; 