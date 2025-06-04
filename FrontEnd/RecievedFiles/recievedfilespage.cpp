#include "recievedfilespage.h"
#include "ui_recievedfilespage.h"
#include "../HomePage/homepage.h"
#include "../../Backend/Decryption/DecryptionManager.h"
#include <QDebug>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QEvent>

#include <QMouseEvent>  //qt mouse events

#include <QMouseEvent>
#include <sodium.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>

// Key Management Includes
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/X3DHKeys/EphemeralKeyPair.h"
#include "../../key_management/KEKManager.h"
#include "../SessionManager/SessionManager.h"

// Helper function to convert std::vector<unsigned char> to QByteArray
QByteArray toQByteArray(const std::vector<unsigned char>& vec) {
    return QByteArray(reinterpret_cast<const char*>(vec.data()), vec.size());
}

// Helper function to convert QByteArray to std::vector<unsigned char>
std::vector<unsigned char> toStdVector(const QByteArray& qba) {
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(qba.constData()),
        reinterpret_cast<const unsigned char*>(qba.constData()) + qba.size()
    );
}


//constructor
RecievedFilesPage::RecievedFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RecievedFilesPage),
    m_receivedFilesManager(new ReceivedFilesManager(this))
{

    ui->setupUi(this);
    // Initialize sodium if it hasn't been already (though DecryptionManager also does it)
    if (sodium_init() < 0) {
        qCritical() << "Failed to initialize libsodium in RecievedFilesPage";
        // Potentially disable functionality or show an error
    }

    // Setup for ReceivedFilesManager
    m_receivedFilesManager->setServerUrl("https://leftovers.gobbler.info"); // Set your server URL
    connect(m_receivedFilesManager, &ReceivedFilesManager::unreadMessagesReceived,
            this, &RecievedFilesPage::handleUnreadMessagesResponse);
    connect(m_receivedFilesManager, &ReceivedFilesManager::fetchMessagesFailed,
            this, &RecievedFilesPage::handleFetchMessagesError);
    // connect(m_receivedFilesManager, &ReceivedFilesManager::sslErrorsSignal, this, &SomeOtherSlotForSslErrors); // Optional: if you want to handle general SSL errors separately

    connect(ui->getFilesButton, &QPushButton::clicked, this, &RecievedFilesPage::on_getFilesButton_clicked);
    connect(ui->decryptButton, &QPushButton::clicked, this, &RecievedFilesPage::on_decryptButton_clicked);
    connect(ui->downloadButton, &QPushButton::clicked, this, &RecievedFilesPage::on_downloadButton_clicked);
    connect(ui->backButton, &QPushButton::clicked, this, &RecievedFilesPage::on_backButton_clicked);


//creates layout for scroll area
    if (!ui->scrollAreaWidgetContents->layout()) {
        QVBoxLayout* scrollLayout = new QVBoxLayout(ui->scrollAreaWidgetContents);
        scrollLayout->setSpacing(10);
        scrollLayout->setContentsMargins(0,0,0,0);
        ui->scrollAreaWidgetContents->setLayout(scrollLayout);
    }

    updateButtonStates();

}
//destructor
RecievedFilesPage::~RecievedFilesPage()
{
    delete ui;
}

//creates ui elements for a file entry
bool RecievedFilesPage::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        QMouseEvent *mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            for (int i = 0; i < receivedFiles.size(); ++i) {
                if (watched == receivedFiles[i].displayBox) {
                    onFileBoxClicked(i);
                    return true; 
                }
            }
        }
    }
    return QDialog::eventFilter(watched, event);
}


// Sender keys remain static for test data generation
static IdentityKeyPair testSenderIdentityKeys;
static EphemeralKeyPair testSenderEphemeralKeys;


void RecievedFilesPage::on_getFilesButton_clicked()
{
    qDebug() << "Get Files button clicked. Fetching from server.";

    // Clear existing UI elements and data
    while (QLayoutItem* item = ui->scrollAreaWidgetContents->layout()->takeAt(0)) {
        if (item->widget()) {
            item->widget()->removeEventFilter(this); // Important if event filters were installed
            delete item->widget();
        }
        delete item;
    }
    receivedFiles.clear();
    selectedFileIndex = -1;
    updateButtonStates(); // Reset buttons

    // Provide UI feedback
    ui->getFilesButton->setEnabled(false);
    ui->getFilesButton->setText("Fetching Messages...");
    // Consider adding a status label if you want more detailed feedback

    m_receivedFilesManager->fetchUnreadMessages();
}

//creates ui for file entry
void RecievedFilesPage::createFileBox(ReceivedFileInfo& fileInfo) {
    QFrame* box = new QFrame(ui->scrollAreaWidgetContents);
    box->setObjectName("fileBox_" + fileInfo.uuid);
    box->setMinimumHeight(90);
    box->setStyleSheet("QFrame { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }");
    box->setCursor(Qt::PointingHandCursor);
    box->installEventFilter(this);

    QVBoxLayout* boxLayout = new QVBoxLayout(box);
    boxLayout->setContentsMargins(10, 5, 10, 5);
    boxLayout->setSpacing(3);

    fileInfo.nameLabel = new QLabel("File: " + fileInfo.fileName, box);
    fileInfo.nameLabel->setStyleSheet("font-weight: bold; font-size: 14px;");

    fileInfo.senderLabel = new QLabel("From: " + fileInfo.sender, box);
    fileInfo.senderLabel->setStyleSheet("font-size: 12px; color: #333;");


    fileInfo.statusLabel = new QLabel(fileInfo.isDecrypted ? "Status: Decrypted" : "Status: Encrypted", box);
    fileInfo.statusLabel->setStyleSheet(fileInfo.isDecrypted ? "color: #28a745;" : "color: #dc3545;");

    boxLayout->addWidget(fileInfo.nameLabel);
    boxLayout->addWidget(fileInfo.senderLabel);
    boxLayout->addWidget(fileInfo.statusLabel);

    fileInfo.displayBox = box;

    QVBoxLayout* scrollLayout = qobject_cast<QVBoxLayout*>(ui->scrollAreaWidgetContents->layout());
    if (scrollLayout) {
        scrollLayout->insertWidget(0, box);
    } else {
        qDebug() << "Error: scrollAreaWidgetContents does not have a QVBoxLayout.";
    }
}

//handles file box selection
void RecievedFilesPage::onFileBoxClicked(int index) {
    if (index < 0 || index >= receivedFiles.size()) {
        qDebug() << "Invalid file index clicked:" << index;
        return;
    }
    qDebug() << "File box clicked, index:" << index << ", Name:" << receivedFiles[index].fileName;
    if (selectedFileIndex != -1 && selectedFileIndex < receivedFiles.size()) {
        if (receivedFiles[selectedFileIndex].displayBox) {
            bool isDec = receivedFiles[selectedFileIndex].isDecrypted;
            QString baseStyle = "QFrame { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }";
            if (isDec) { 
                 baseStyle = "QFrame { background-color: #e8f5e9; border: 1px solid #4CAF50; border-radius: 4px; }";
            }
            receivedFiles[selectedFileIndex].displayBox->setStyleSheet(baseStyle);
        }
    }
    selectedFileIndex = index;
    if (receivedFiles[selectedFileIndex].displayBox) {
        bool isDec = receivedFiles[selectedFileIndex].isDecrypted;
        QString selectedStyle = "QFrame { background-color: #e0e0e0; border: 2px solid #007bff; border-radius: 4px; }";
         if (isDec) {
            selectedStyle = "QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }";
        }
        receivedFiles[selectedFileIndex].displayBox->setStyleSheet(selectedStyle);
    }
    updateButtonStates();
}


//updates enabled state and style of action buttons
void RecievedFilesPage::updateButtonStates() {
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        ui->decryptButton->setEnabled(false);
        ui->downloadButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        return;
    }
    const auto& selectedFile = receivedFiles[selectedFileIndex];
    if (!selectedFile.isDecrypted) {
        ui->decryptButton->setEnabled(true);
        ui->downloadButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: white; background-color: #2196F3; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
    } else { 
        ui->decryptButton->setEnabled(false);
        ui->downloadButton->setEnabled(true);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: white; background-color: #4CAF50; border: none; border-radius: 15px; font-size: 22px;");
    }
}

//handles decrypt button click
void RecievedFilesPage::on_decryptButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size() || receivedFiles[selectedFileIndex].isDecrypted) {
        qDebug() << "Decrypt button: No valid file selected or file already processed for decryption.";
        return;
    }

    ReceivedFileInfo& selectedFile = receivedFiles[selectedFileIndex];
    qDebug() << "Attempting to process file for decryption:" << selectedFile.fileName;

    if (selectedFile.derivedDecryptionKey.isEmpty()) {
        qDebug() << "Step 1: Retrieving receiver keys and deriving X3DH key for" << selectedFile.fileName;

        // --- KEK Retrieval --- 
        QByteArray kek_qba = SessionManager::getInstance()->getDecryptedKEK();
        if (kek_qba.isEmpty()) {
            QMessageBox::critical(this, "KEK Error", "Failed to retrieve KEK. User session might be invalid. Please log in again.");
            qDebug() << "Failed to retrieve KEK from SessionManager.";
            return;
        }
        qDebug() << "Successfully retrieved KEK from SessionManager.";
        std::vector<unsigned char> kekVector = toStdVector(kek_qba);
        // --- End KEK Retrieval ---

        std::string userPackage = "leftovers.project"; 
        std::string userId = "tempUser"; 
        KEKManager kekManager(userPackage, userId);

        QByteArray receiverIdentityPrivEd_qba;
        QByteArray receiverSignedPrekeyPriv_qba;

        try {
            std::vector<unsigned char> receiverIdPrivVec = kekManager.decryptStoredPrivateIdentityKey(kekVector);
            receiverIdentityPrivEd_qba = toQByteArray(receiverIdPrivVec);
            qDebug() << "Retrieved Receiver Identity Private Key (first 5 bytes):" << receiverIdentityPrivEd_qba.left(5).toHex();

            std::vector<unsigned char> receiverSpkPrivVec = kekManager.decryptStoredSignedPreKey(kekVector);
            receiverSignedPrekeyPriv_qba = toQByteArray(receiverSpkPrivVec);
            qDebug() << "Retrieved Receiver Signed PreKey Private Key (first 5 bytes):" << receiverSignedPrekeyPriv_qba.left(5).toHex();

        } catch (const std::runtime_error& e) {
            QMessageBox::critical(this, "Key Retrieval Error", "Failed to retrieve receiver keys from keychain: " + QString::fromUtf8(e.what()));
            qDebug() << "Key Retrieval Error:" << e.what();
            return;
        }
        
        if (receiverIdentityPrivEd_qba.isEmpty() || receiverSignedPrekeyPriv_qba.isEmpty()) {
             QMessageBox::critical(this, "Key Retrieval Error", "One or more receiver private keys are empty after retrieval.");
            return;
        }

        if (selectedFile.senderEphemeralPublicKey.isEmpty() || selectedFile.senderIdentityPublicKeyEd.isEmpty()) {
            QMessageBox::critical(this, "Decryption Error", "Sender public keys are missing for the selected file.");
            return;
        }

        DecryptionManager decryptionManager;
        selectedFile.derivedDecryptionKey = decryptionManager.deriveFileDecryptionKey(
            selectedFile, 
            receiverIdentityPrivEd_qba, 
            receiverSignedPrekeyPriv_qba
        );

        if (selectedFile.derivedDecryptionKey.isEmpty()) {
            QMessageBox::critical(this, "Key Derivation Failed", "Could not derive X3DH key for " + selectedFile.fileName);
            return;
        }
        qDebug() << "Successfully derived X3DH key for:" << selectedFile.fileName << "Key (first 5 bytes):" << selectedFile.derivedDecryptionKey.left(5).toHex();
    } else {
         qDebug() << "X3DH key already available for:" << selectedFile.fileName;
    }

    // Step 2: Decrypt Metadata
    qDebug() << "Step 2: Decrypting metadata for" << selectedFile.fileName;
    DecryptionManager decryptionManager; // Can re-use or make manager member if preferred
    selectedFile.decryptedMetadataJsonString = decryptionManager.decryptFileMetadata(
        selectedFile.encryptedMetadata,
        selectedFile.metadataNonce,
        selectedFile.derivedDecryptionKey
    );

    if (selectedFile.decryptedMetadataJsonString.isEmpty()) {
        QMessageBox::warning(this, "Metadata Decryption Failed", 
                             "Could not decrypt metadata for " + selectedFile.fileName + ". It might be corrupted, or keys might not match the encrypted data.");
        // Even if metadata decryption fails, we might still mark the key as derived and allow download attempt later
        // For now, let's not change isDecrypted status if only metadata fails, but key is derived.
        // The definition of "isDecrypted" might need refinement (key derived vs metadata decrypted vs content decrypted)
        qDebug() << "Metadata decryption failed for:" << selectedFile.fileName;
    } else {
        qDebug() << "Successfully decrypted metadata for:" << selectedFile.fileName;
        qDebug() << "Decrypted Metadata JSON:" << selectedFile.decryptedMetadataJsonString;
        // Optionally parse and use metadata
        QJsonDocument doc = QJsonDocument::fromJson(selectedFile.decryptedMetadataJsonString.toUtf8());
        if (!doc.isNull() && doc.isObject()) {
            QJsonObject jsonObj = doc.object();
            qDebug() << "Parsed metadata - UUID:" << jsonObj.value("uuid").toString() 
                     << ", Filename:" << jsonObj.value("filename").toString();
            // You could update UI elements here based on decrypted metadata if needed.
        } else {
            qDebug() << "Failed to parse decrypted metadata as JSON.";
        }
    }

    // For now, we'll consider the file "decrypted" if the key derivation was successful,
    // as the metadata might be optional or handled differently. User can attempt download.
    selectedFile.isDecrypted = !selectedFile.derivedDecryptionKey.isEmpty();
 
    if (selectedFile.isDecrypted) {
         if (selectedFile.displayBox) {
            selectedFile.statusLabel->setText("Status: Decrypted (Key Ready)"); // Update status
            selectedFile.statusLabel->setStyleSheet("color: #28a745;");
            selectedFile.displayBox->setStyleSheet("QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }");
        }
        QMessageBox::information(this, "Processing Complete", 
                                 selectedFile.fileName + " has been processed. X3DH key is derived. Metadata decryption attempted.");
    }
    
    updateButtonStates();
}


//handles download button click
void RecievedFilesPage::on_downloadButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size() || !receivedFiles[selectedFileIndex].isDecrypted) {
         qDebug() << "Download button clicked, but no valid decrypted file selected.";
        return;
    }
    const auto& fileToDownload = receivedFiles[selectedFileIndex];
    qDebug() << "Downloading file:" << fileToDownload.fileName;
    QMessageBox::information(this, "Download Started", "Downloading " + fileToDownload.fileName + "...");
    updateButtonStates();
    QMessageBox::information(this, "Download Complete", fileToDownload.fileName + " has been 'downloaded' (simulated).");
}

//handles back button click
void RecievedFilesPage::on_backButton_clicked()
{
    reject();
    qDebug() << "Back button clicked, closing RecievedFilesPage.";
}

// formats file size into human readable string
QString RecievedFilesPage::formatFileSize(qint64 size) {
    if (size < 1024)
        return QString("%1 bytes").arg(size);
    else if (size < 1024 * 1024)
        return QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    else if (size < 1024 * 1024 * 1024)
        return QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    else
        return QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}

// Updates file display info
void RecievedFilesPage::updateFileInfoDisplay(int index) {
    Q_UNUSED(index);
}

// New slot to handle successful message fetch
void RecievedFilesPage::handleUnreadMessagesResponse(const QByteArray &serverResponse)
{
    qDebug() << "Received unread messages response from manager.";
    ui->getFilesButton->setEnabled(true);
    ui->getFilesButton->setText("Get Files");

    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(serverResponse, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "Failed to parse messages JSON:" << parseError.errorString();
        QMessageBox::critical(this, "Error", "Failed to parse server response for messages.");
        return;
    }

    if (!jsonDoc.isObject()) {
        qWarning() << "Messages JSON is not an object.";
        QMessageBox::critical(this, "Error", "Invalid server response format (not an object).");
        return;
    }

    QJsonObject rootObj = jsonDoc.object();
    if (!rootObj.contains("messages") || !rootObj["messages"].isArray()) {
        qWarning() << "Messages JSON does not contain a 'messages' array.";
        if (rootObj.contains("message") && rootObj["message"].isString()){
             QMessageBox::information(this, "Messages", rootObj["message"].toString()); // Display server message if no messages array (e.g. "No new messages")
        } else {
            QMessageBox::critical(this, "Error", "Invalid server response format (no messages array).");
        }
        return;
    }

    QJsonArray messagesArray = rootObj["messages"].toArray();
    if (messagesArray.isEmpty()) {
        QMessageBox::information(this, "Inbox", "No new messages found.");
        return;
    }

    for (const QJsonValue &msgValue : messagesArray) {
        QJsonObject msgObj = msgValue.toObject();
        ReceivedFileInfo fileInfo;

        // Populate ReceivedFileInfo from msgObj
        fileInfo.uuid = msgObj.value("message_id").toString(); // Or .toInt() then .toString()
        fileInfo.sender = msgObj.value("sender_username").toString("Unknown Sender");

        // For fileName, use a descriptive placeholder. Actual name is in encrypted metadata.
        fileInfo.fileName = QString("Encrypted File from %1").arg(fileInfo.sender);

        fileInfo.senderEphemeralPublicKey = QByteArray::fromBase64(msgObj.value("ephemeral_key").toString().toUtf8());
        fileInfo.encryptedMetadata = QByteArray::fromBase64(msgObj.value("encrypted_file_metadata").toString().toUtf8());
        fileInfo.metadataNonce = QByteArray::fromBase64(msgObj.value("encrypted_metadata_nonce").toString().toUtf8());

        // Other fields that might be relevant or have defaults
        fileInfo.fileSize = 0; // Placeholder, actual size might be in decrypted metadata
        fileInfo.isDecrypted = false;
        fileInfo.isDownloaded = false;
        fileInfo.index = receivedFiles.size();
        // senderIdentityPublicKeyEd will be needed for X3DH. This might need to be fetched separately
        // if not part of the message payload, or if you are not using a full prekey bundle system for messages.
        // For now, leave it empty or set a placeholder if decryption logic expects it.
        // fileInfo.senderIdentityPublicKeyEd = QByteArray();

        receivedFiles.append(fileInfo);
        createFileBox(receivedFiles.last());
    }
    updateButtonStates(); // Update button states based on new files
}

// New slot to handle errors from message fetch
void RecievedFilesPage::handleFetchMessagesError(const QString &error)
{
    qDebug() << "Error fetching messages:" << error;
    ui->getFilesButton->setEnabled(true);
    ui->getFilesButton->setText("Get Files");
    QMessageBox::critical(this, "Error Fetching Messages", error);
}