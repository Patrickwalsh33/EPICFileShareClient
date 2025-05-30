#include "uploadManager.h"
#include <QDebug>
#include <QNetworkAccessManager>
#include <QNetworkRequest>
#include <QSslSocket>
#include <QSslConfiguration>
#include <QNetworkReply>


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

    connect(currentReply, &QNetworkReply::uploadProgress,
            this, &uploadManager::handleUploadProgress);
    connect(currentReply, &QNetworkReply::finished,
            this, &uploadManager::handleUploadFinished);
    connect(currentReply, &QNetworkReply::sslErrors,
            this, &uploadManager::handleSslErrors);
    connect(currentReply, &QNetworkReply::errorOccurred,
            this, &uploadManager::handleNetworkError);
    return true;
}

void uploadManager::handleUploadProgress(qint64 bytesSent, qint64 bytesTotal)
{
    emit uploadProgress(bytesSent, bytesTotal);
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

bool uploadManager::encryptFileWithDEK(const QByteArray &plainData, std::vector<unsigned char> &dek,
                                       QByteArray &ciphertext, QByteArray &nonce) {
    unsigned long long ciphertext_len;
    std::vector<unsigned char> cipherBuf(plainData.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    std::vector<unsigned char> nonceBuf(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonceBuf.data(), nonceBuf.size());

    encrypt_with_chacha20(
            reinterpret_cast<const unsigned char*>(plainData.constData()),
            plainData.size(),
            reinterpret_cast<const unsigned char*>(dek.data()),
            cipherBuf.data(),
            &ciphertext_len,
            nonceBuf.data()
    );

    ciphertext = QByteArray(reinterpret_cast<const char*>(cipherBuf.data()), ciphertext_len);
    nonce = QByteArray(reinterpret_cast<const char*>(nonceBuf.data()), nonceBuf.size());
    return true;
}

bool uploadManager::getSharedSecret(unsigned char *sharedSecret, size_t length) {
    return run_x3dh(sharedSecret, length);
}

bool uploadManager::deriveKeyFromSharedSecret(const unsigned char *sharedSecret,
                                              unsigned char *derivedKey,
                                              const char *context,
                                              uint64_t subkeyId) {
    return derive_key_from_shared_secret(sharedSecret, derivedKey, context, subkeyId);
}

bool uploadManager::encryptDEK(std::vector<unsigned char> &dek,
                               const unsigned char *derivedKey,
                               QByteArray &encryptedDek,
                               QByteArray &dekNonce) {
    std::vector<unsigned char> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> encrypted(dek.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long encLen = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encrypted.data(), &encLen,
            reinterpret_cast<const unsigned char*>(dek.data()), dek.size(),
            nullptr, 0,
            nullptr,
            nonce.data(),
            derivedKey) != 0) {
        return false;
    }

    encryptedDek = QByteArray(reinterpret_cast<const char*>(encrypted.data()), encLen);
    dekNonce = QByteArray(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    return true;
}

bool uploadManager::decryptDEK(const QByteArray &encryptedDek, size_t encryptedDekLen,
                               const QByteArray &dekNonce,
                               const unsigned char *derivedKey,
                               QByteArray &decryptedDek) {
    std::vector<unsigned char> decrypted(encryptedDekLen);
    unsigned long long decLen = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decLen,
            nullptr,
            reinterpret_cast<const unsigned char*>(encryptedDek.constData()), encryptedDekLen,
            nullptr, 0,
            reinterpret_cast<const unsigned char*>(dekNonce.constData()),
            derivedKey) != 0) {
        return false;
    }

    decryptedDek = QByteArray(reinterpret_cast<const char*>(decrypted.data()), decLen);
    return true;
}

