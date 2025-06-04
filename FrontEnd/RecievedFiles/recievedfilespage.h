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
    QString uuid;
    QString fileName;
    QString sender;
    qint64 fileSize;
    QByteArray encryptedData;       // This would be the actual encrypted file content
    QByteArray decryptedData;       // To store data after actual decryption of content
    QByteArray encryptedMetadata;   // Assuming metadata is also received encrypted
    QByteArray metadataNonce;       // Nonce for metadata decryption
    QByteArray fileNonce;           // Nonce for file content decryption (if separate)

    // Keys related to X3DH and key derivation
    QByteArray senderEphemeralPublicKey; // EK_sender_pub
    QByteArray senderIdentityPublicKeyEd;  // ID_sender_pub_Ed (fetched or part of pre-bundle)
    QByteArray derivedDecryptionKey;     // The final key for decrypting file content/metadata

    QString decryptedMetadataJsonString; // To store the decrypted metadata

    bool isDecrypted = false;       // Status: if derivedDecryptionKey is available and metadata potentially decrypted
    bool isDownloaded = false;
    int index; // To identify the file in the QVector

    // UI elements associated with this file
    QFrame* displayBox = nullptr;
    QLabel* nameLabel = nullptr;
    QLabel* senderLabel = nullptr;
    QLabel* statusLabel = nullptr;
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