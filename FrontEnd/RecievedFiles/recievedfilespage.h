#ifndef RECIEVEDFILESPAGE_H
#define RECIEVEDFILESPAGE_H


#include "../ReceivedFilesPage/receivedfilesmanager.h"
#include <QDialog>     //Base class for dialog windows in QT
#include <QVector>     // QT vector class
#include <QString>      // qt string class
#include <QByteArray>   //qt byte array
#include <QLabel>       //qt label class
#include <QFrame>      //qt frame widget

//prevent naming collisons and are good for organsing code
namespace Ui {
class RecievedFilesPage;
}

// Struct to hold information about each received file
struct ReceivedFileInfo {
    QString uuid; // Message ID
    QString fileName; // Initially placeholder, then actual from metadata
    QString sender;
    qint64 fileSize; // Placeholder, actual size might be in metadata
    bool isDecrypted; // True if X3DH key derived and metadata processed
    bool isDownloaded; // True if encrypted file blob has been downloaded
    QByteArray senderEphemeralPublicKey;
    QByteArray senderIdentityPublicKeyEd; // Ed25519
    QByteArray derivedDecryptionKey; // Result of X3DH, used for metadata decryption
    QByteArray encryptedMetadata;
    QByteArray metadataNonce;
    QString decryptedMetadataJsonString;
    QString actualFileUuid_; // UUID of the actual file, from metadata

    // New fields for file data decryption and details
    QByteArray dek; // Data Encryption Key, from decrypted metadata
    QByteArray fileNonce; // Nonce for file data encryption, from decrypted metadata
    QByteArray encryptedData; // Downloaded encrypted file content
    QByteArray decryptedData; // Decrypted file content
    QString mimeType; // MIME type from decrypted metadata
    // 'fileName' will be updated to actual filename from metadata, so no separate 'actualFileName' needed here.

    QLabel* nameLabel = nullptr;
    QLabel* senderLabel = nullptr;
    QLabel* statusLabel = nullptr;
    QLabel* typeLabel = nullptr; // For MIME type or file extension
    QFrame* displayBox = nullptr;
    int index = -1;
};

class RecievedFilesPage : public QDialog
{
    Q_OBJECT   //special at macro

public:
    //constructor
    explicit RecievedFilesPage(QWidget *parent = nullptr);
    //destructor
    ~RecievedFilesPage();

protected:
    //overide event fileter to handle mouse clicks
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void on_backButton_clicked();
    void on_getFilesButton_clicked(); // Slot for the new button
    void on_decryptButton_clicked();
    void on_downloadButton_clicked();
    void onFileBoxClicked(int index); // Slot for when a file box is clicked

    // Slots for handling responses from ReceivedFilesManager
    void handleUnreadMessagesResponse(const QByteArray &serverResponse);
    void handleFetchMessagesError(const QString &error);
    void handleSenderKeysResponse(const QByteArray &serverResponse); // New slot for sender keys
    void handleFetchSenderKeysError(const QString &error);      // New slot for sender key errors
    // Slots for handling file download responses
    void handleFileDownloadSuccess(const QByteArray &encryptedFileBytes, const QString &file_uuid_ref);
    void handleFileDownloadError(const QString &error, const QString &file_uuid_ref);

private:
    Ui::RecievedFilesPage *ui;    //pointer to ui
    QVector<ReceivedFileInfo> receivedFiles;  //list of files
    int selectedFileIndex = -1; // Index of the currently selected file, -1 if none
    ReceivedFilesManager *m_receivedFilesManager;

    void createFileBox(ReceivedFileInfo& fileInfo);
    void updateButtonStates();
    void updateFileInfoDisplay(int index); // To update details of a selected file (optional)
    QString formatFileSize(qint64 size); // Helper for formatting file size
};

#endif