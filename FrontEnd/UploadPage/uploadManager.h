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
    bool uploadFile(const QByteArray &encryptedData, const QString &file_uuid, const QString &originalFileName);

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
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    void setupSslConfiguration();

    QString serverUrl;
    QByteArray currentDek;
    QNetworkReply *currentReply;
    QNetworkAccessManager *networkManager;

    // Enum to track the type of the current network operation
    enum RequestType_ {
        RetrieveKeys,
        SendFile
    };
    RequestType_ currentRequestType;

};

