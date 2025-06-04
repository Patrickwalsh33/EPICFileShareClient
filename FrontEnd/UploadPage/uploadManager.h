#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QSslError>
#include <QNetworkReply>
#include <QUrlQuery>

class uploadManager : public QObject
{
    Q_OBJECT

public:
    explicit uploadManager(QObject *parent = nullptr);
    ~uploadManager();

    void setServerUrl(const QString &url);
    bool requestRecipientKeys(const QString& username);
    bool uploadFile(const QByteArray &encryptedData, 
                    const QString &file_uuid, 
                    const QString &originalFileName,
                    const QString &recipientUsername,
                    const QByteArray &ephemeralPublicKey,
                    const QByteArray &encryptedFileMetadata,
                    const QByteArray &metadataNonce);

signals:
    void recipientKeysFailed(const QString &error);
    void recipientKeysReceived(const QByteArray &data);
    void uploadSucceeded(const QByteArray &serverResponse);
    void uploadFailed(const QString &error);
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void sslError(const QString &error);


private slots:
    void handleKeysReceived();
    void handleUploadFinished();
    void handleMetadataShareFinished();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    void setupSslConfiguration();

    QString serverUrl;
    QByteArray currentDek;
    QNetworkReply *currentReply;
    QNetworkAccessManager *networkManager;

    // Member variables to store data for the second POST request (metadata share)
    QString m_recipientUsername_temp;
    QByteArray m_ephemeralPublicKey_temp;
    QByteArray m_encryptedFileMetadata_temp;
    QByteArray m_metadataNonce_temp;

    // Enum to track the type of the current network operation
    enum RequestType_ {
        RetrieveKeys,
        SendFile,
        ShareMetadata
    };
    RequestType_ currentRequestType;

};

