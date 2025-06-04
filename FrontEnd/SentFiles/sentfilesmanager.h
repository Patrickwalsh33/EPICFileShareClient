#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QSslError>

class SentFilesManager : public QObject
{
    Q_OBJECT

public:
    explicit SentFilesManager(QObject *parent = nullptr);
    ~SentFilesManager();

    void fetchOwnedFileUuids();
    void deleteFile(const QString &file_uuid);
    void setServerUrl(const QString &url);

signals:
    void ownedFileUuidsReceived(const QByteArray &serverResponse);
    void fetchOwnedFileUuidsFailed(const QString &error);
    void fileDeleteSucceeded(const QString &deleted_file_uuid, const QByteArray &serverResponse);
    void fileDeleteFailed(const QString &file_uuid, const QString &error);
    void sslErrorsSignal(const QString &error);

private slots:
    void handleOwnedFileUuidsResponse();
    void handleFileDeleteResponse();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError errorCode);

private:
    QNetworkAccessManager *networkManager;
    QNetworkReply *currentReply;
    QString serverUrl;
    
    enum RequestType_ {
        FetchOwnedUUIDs,
        DeleteFile
    };
    RequestType_ currentRequestType;
    QString m_currentlyProcessedFileUuid;
}; 