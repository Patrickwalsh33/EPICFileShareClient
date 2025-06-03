
#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QSslError>
#include <QNetworkReply>

class UserAuthentication; // Forward declaration to avoid circular dependency

class uploadManager : public QObject
{
    Q_OBJECT

public:
    explicit uploadManager(UserAuthentication* userAuth, QObject *parent = nullptr);
    ~uploadManager();

    void setServerUrl(const QString &url);
    bool uploadFileServer(const QByteArray &fileData, const QUuid &uuid);
    bool requestRecipientKeys(const QString &username);
    bool uploadFileShareRequest(const QByteArray &metadata, const QByteArray &ephemeralKey, const QByteArray &en_file_metadata_nonce);
    UserAuthentication* m_userAuth;


signals:
    void uploadSucceeded(const QByteArray &EncryptedDek);
    void uploadFailed(const QString &error);
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void sslError(const QString &error);

    void recipientKeysReceived(const QString &username, const QByteArray &identityPublicKey, const QByteArray &signedPreKeyPublicKey, const QByteArray &signedPreKeySignature);
    void recipientKeysFailed(const QString &error);
    void fileShareRequestSucceeded();
    void fileShareRequestFailed(const QString &error);

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
