
#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QSslError>
#include <QNetworkReply>

class uploadManager : public QObject
{
    Q_OBJECT

public:
    explicit uploadManager(QObject *parent = nullptr);
    ~uploadManager();

    void setServerUrl(const QString &url);
    bool uploadFile(const QByteArray &fileData, const QByteArray &EncryptedDek, const QUuid &uuid, const QString &jwtToken);
    bool requestRecipientKeys(const QString &username);

signals:
    void uploadSucceeded(const QByteArray &EncryptedDek);
    void uploadFailed(const QString &error);
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void sslError(const QString &error);

    void recipientKeysReceived(const QString &username,
                               const QByteArray &identityPublicKey,
                               const QByteArray &signedPreKeyPublicKey,
                               const QByteArray &signedPreKeySignature,
                               const QList<QByteArray> &oneTimeKeys);
    void recipientKeysFailed(const QString &error);

private slots:
    void handleUploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void handleUploadFinished();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);
    void handleKeyRetrievalFinished();

private:
    void setupSslConfiguration();

    QString serverUrl;
    QByteArray currentDek;
    QNetworkReply *currentReply;
    QNetworkAccessManager *networkManager;

    enum RequestType { Upload, KeyRetrieval } currentRequestType;


};
