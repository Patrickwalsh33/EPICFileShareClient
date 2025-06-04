#ifndef RECIEVEDFILESPAGE_H
#define RECIEVEDFILESPAGE_H


#include "../ReceivedFilesPage/receivedfilesmanager.h"
#include <QDialog>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QLabel>
#include <QFrame>


namespace Ui {
class RecievedFilesPage;
}

// Struct to hold information about each received file
struct ReceivedFileInfo {
    QString uuid;
    QString fileName;
    QString sender;
    qint64 fileSize;
    bool isDecrypted; // True if X3DH key derived and metadata processed
    bool isDownloaded; // True if encrypted file blob has been downloaded
    QByteArray senderEphemeralPublicKey;
    QByteArray senderIdentityPublicKeyEd;
    QByteArray derivedDecryptionKey; // Result of X3DH, used for metadata decryption
    QByteArray encryptedMetadata;
    QByteArray metadataNonce;
    QString decryptedMetadataJsonString;
    QString actualFileUuid_;

    //fields for file data decryption and details
    QByteArray dek;
    QByteArray fileNonce;
    QByteArray encryptedData;
    QByteArray decryptedData;
    QString mimeType;
    bool isSavedToDisk = false;

    QLabel* nameLabel = nullptr;
    QLabel* senderLabel = nullptr;
    QLabel* statusLabel = nullptr;
    QLabel* typeLabel = nullptr;
    QFrame* displayBox = nullptr;
    int index = -1;
};

class RecievedFilesPage : public QDialog
{
    Q_OBJECT

public:
    explicit RecievedFilesPage(QWidget *parent = nullptr);
    ~RecievedFilesPage();

protected:
    //overide event fileter to handle mouse clicks
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void on_backButton_clicked();
    void on_getFilesButton_clicked();
    void on_decryptButton_clicked();
    void on_downloadButton_clicked();
    void onFileBoxClicked(int index);

    // Slots for handling responses from ReceivedFilesManager
    void handleUnreadMessagesResponse(const QByteArray &serverResponse);
    void handleFetchMessagesError(const QString &error);
    void handleSenderKeysResponse(const QByteArray &serverResponse);
    void handleFetchSenderKeysError(const QString &error);
    // Slots for handling file download responses
    void handleFileDownloadSuccess(const QByteArray &encryptedFileBytes, const QString &file_uuid_ref);
    void handleFileDownloadError(const QString &error, const QString &file_uuid_ref);

private:
    Ui::RecievedFilesPage *ui;
    QVector<ReceivedFileInfo> receivedFiles;
    int selectedFileIndex = -1;
    ReceivedFilesManager *m_receivedFilesManager;

    void createFileBox(ReceivedFileInfo& fileInfo);
    void updateButtonStates();
    void updateFileInfoDisplay(int index);
    QString formatFileSize(qint64 size);
};

#endif