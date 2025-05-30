#pragma once

#include <QObject>
#include <QString>
#include <QByteArray>
#include <QSslError>
#include <QNetworkReply>
#include "sodium.h"
#include "../crypto/crypto_utils.h"
#include "../X3DH/X3DH.h"

class uploadManager : public QObject
{
    Q_OBJECT

public:
    explicit uploadManager(QObject *parent = nullptr);
    ~uploadManager();

    void setServerUrl(const QString &url);
    bool uploadFile(const QByteArray &fileData, const QByteArray &EncryptedDek); //the filepath might have to be changed to a QByteArray if we want to send the file contents directly
    bool encryptFileWithDEK(const QByteArray &plainData, std::vector<unsigned char> &dek,
                            QByteArray &ciphertext, QByteArray &nonce);

    bool getSharedSecret(unsigned char *sharedSecret, size_t length);

    bool deriveKeyFromSharedSecret(const unsigned char *sharedSecret,
                                   unsigned char *derivedKey,
                                   const char *context,
                                   uint64_t subkeyId);

    bool encryptDEK(std::vector<unsigned char> &dek,
                    const unsigned char *derivedKey,
                    QByteArray &encryptedDek,
                    QByteArray &dekNonce);

    bool decryptDEK(const QByteArray &encryptedDek, size_t encryptedDekLen,
                    const QByteArray &dekNonce,
                    const unsigned char *derivedKey,
                    QByteArray &decryptedDek);


signals:
    void uploadSucceeded(const QByteArray &EncryptedDek);
    void uploadFailed(const QString &error);
    void uploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void sslError(const QString &error);

private slots:
    void handleUploadProgress(qint64 bytesSent, qint64 bytesTotal);
    void handleUploadFinished();
    void handleSslErrors(const QList<QSslError> &errors);
    void handleNetworkError(QNetworkReply::NetworkError error);

private:
    void setupSslConfiguration();

    QString serverUrl;
    QByteArray currentDek;
    QNetworkReply *currentReply;
    QNetworkAccessManager *networkManager;

};
