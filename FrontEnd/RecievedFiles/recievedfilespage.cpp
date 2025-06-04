#include "recievedfilespage.h"
#include "ui_recievedfilespage.h"
#include "../HomePage/homepage.h"
#include "../../Backend/Decryption/DecryptionManager.h"
#include <QDebug>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QEvent>
#include <QFileDialog>

#include <QMouseEvent>

#include <sodium.h>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>


#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/X3DHKeys/EphemeralKeyPair.h"
#include "../../key_management/KEKManager.h"
#include "../SessionManager/SessionManager.h"

// convert std::vector<unsigned char> to QByteArray
QByteArray toQByteArray(const std::vector<unsigned char>& vec) {
    return QByteArray(reinterpret_cast<const char*>(vec.data()), vec.size());
}

// convert QByteArray to std::vector<unsigned char>
std::vector<unsigned char> toStdVector(const QByteArray& qba) {
    return std::vector<unsigned char>(
        reinterpret_cast<const unsigned char*>(qba.constData()),
        reinterpret_cast<const unsigned char*>(qba.constData()) + qba.size()
    );
}



RecievedFilesPage::RecievedFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RecievedFilesPage),
    m_receivedFilesManager(new ReceivedFilesManager(this))
{

    ui->setupUi(this);
    // Initialize sodium if it hasn't been already
    if (sodium_init() < 0) {
        qCritical() << "Failed to initialize libsodium in RecievedFilesPage";
    }


    m_receivedFilesManager->setServerUrl("https://leftovers.gobbler.info");
    connect(m_receivedFilesManager, &ReceivedFilesManager::unreadMessagesReceived,
            this, &RecievedFilesPage::handleUnreadMessagesResponse);
    connect(m_receivedFilesManager, &ReceivedFilesManager::fetchMessagesFailed,
            this, &RecievedFilesPage::handleFetchMessagesError);
    // Sender Keys
    connect(m_receivedFilesManager, &ReceivedFilesManager::senderKeysReceived,
            this, &RecievedFilesPage::handleSenderKeysResponse);
    connect(m_receivedFilesManager, &ReceivedFilesManager::fetchSenderKeysFailed,
            this, &RecievedFilesPage::handleFetchSenderKeysError);
    // File Download
    connect(m_receivedFilesManager, &ReceivedFilesManager::fileDownloadSucceeded,
            this, &RecievedFilesPage::handleFileDownloadSuccess);
    connect(m_receivedFilesManager, &ReceivedFilesManager::fileDownloadFailed,
            this, &RecievedFilesPage::handleFileDownloadError);

    connect(ui->getFilesButton, &QPushButton::clicked, this, &RecievedFilesPage::on_getFilesButton_clicked);
    connect(ui->decryptButton, &QPushButton::clicked, this, &RecievedFilesPage::on_decryptButton_clicked);
    connect(ui->downloadButton, &QPushButton::clicked, this, &RecievedFilesPage::on_downloadButton_clicked);
    connect(ui->backButton, &QPushButton::clicked, this, &RecievedFilesPage::on_backButton_clicked);



    if (!ui->scrollAreaWidgetContents->layout()) {
        QVBoxLayout* scrollLayout = new QVBoxLayout(ui->scrollAreaWidgetContents);
        scrollLayout->setSpacing(10);
        scrollLayout->setContentsMargins(0,0,0,0);
        ui->scrollAreaWidgetContents->setLayout(scrollLayout);
    }

    updateButtonStates();

}

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
            item->widget()->removeEventFilter(this);
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


    m_receivedFilesManager->fetchUnreadMessages();
}

//creates ui for file entry
void RecievedFilesPage::createFileBox(ReceivedFileInfo& fileInfo) {
    QFrame* box = new QFrame(ui->scrollAreaWidgetContents);
    box->setObjectName("fileBox_" + fileInfo.uuid);
    box->setMinimumHeight(110);
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

    fileInfo.typeLabel = new QLabel("Type: Unknown", box);
    fileInfo.typeLabel->setStyleSheet("font-size: 12px; color: #555;");

    fileInfo.statusLabel = new QLabel(fileInfo.isDecrypted ? "Status: Decrypted" : "Status: Encrypted", box);
    fileInfo.statusLabel->setStyleSheet(fileInfo.isDecrypted ? "color: #28a745;" : "color: #dc3545;");

    boxLayout->addWidget(fileInfo.nameLabel);
    boxLayout->addWidget(fileInfo.senderLabel);
    boxLayout->addWidget(fileInfo.typeLabel);
    boxLayout->addWidget(fileInfo.statusLabel);

    fileInfo.displayBox = box;

    QVBoxLayout* scrollLayout = qobject_cast<QVBoxLayout*>(ui->scrollAreaWidgetContents->layout());
    if (scrollLayout) {
        scrollLayout->insertWidget(0, box);
    } else {
        qDebug() << "Error: scrollAreaWidgetContents does not have a QVBoxLayout.";
    }
}


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



void RecievedFilesPage::updateButtonStates() {
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        ui->decryptButton->setEnabled(false);
        ui->downloadButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
        ui->downloadButton->setText("Download File");
        return;
    }

    const auto& selectedFile = receivedFiles[selectedFileIndex];

    // Decrypt Button (for X3DH/Metadata)
    if (!selectedFile.isDecrypted) {
        ui->decryptButton->setEnabled(true);
        ui->decryptButton->setStyleSheet("color: white; background-color: #2196F3; border: none; border-radius: 15px; font-size: 22px;");
    } else {
        ui->decryptButton->setEnabled(false);
        ui->decryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
    }

    // Download/Save Button
    if (selectedFile.isSavedToDisk) {
        ui->downloadButton->setEnabled(false);
        ui->downloadButton->setText("File Saved");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #d0d0d0; border: none; border-radius: 15px; font-size: 22px;");
    } else if (selectedFile.isDecrypted && !selectedFile.decryptedData.isEmpty()) { // Metadata processed AND file data decrypted
        ui->downloadButton->setEnabled(true);
        ui->downloadButton->setText("Save File");
        ui->downloadButton->setStyleSheet("color: white; background-color: #4CAF50; border: none; border-radius: 15px; font-size: 22px;");
    } else if (selectedFile.isDecrypted && selectedFile.actualFileUuid_.isEmpty()) { // Metadata processed but UUID missing (error state)
        ui->downloadButton->setEnabled(false);
        ui->downloadButton->setText("Download Error");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
    } else if (selectedFile.isDecrypted) { // Metadata processed, file ready for encrypted download
        ui->downloadButton->setEnabled(true); // Allow clicking to initiate download if not yet downloaded
        ui->downloadButton->setText("Download Encrypted");


        ui->downloadButton->setStyleSheet("color: white; background-color: #FF9800; border: none; border-radius: 15px; font-size: 22px;"); // Orange for "Download Encrypted"
    } else { // Not yet X3DH/metadata processed, so download is not an option yet
        ui->downloadButton->setEnabled(false);
        ui->downloadButton->setText("Download File");
        ui->downloadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 15px; font-size: 22px;");
    }
}

void RecievedFilesPage::on_decryptButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        qDebug() << "Decrypt button: No file selected.";
        return;
    }

    ReceivedFileInfo& selectedFile = receivedFiles[selectedFileIndex];

    if (selectedFile.isDecrypted) {
        qDebug() << "File already processed and key derived/decryption attempted for:" << selectedFile.fileName;
        QMessageBox::information(this, "Already Processed", selectedFile.fileName + " has already been processed.");
        return;
    }

    qDebug() << "Decrypt button clicked for file:" << selectedFile.fileName << "from sender:" << selectedFile.sender;

    // Disable button and show feedback
    ui->decryptButton->setEnabled(false);
    ui->decryptButton->setText("Fetching Sender Keys...");

    m_receivedFilesManager->requestSenderKeys(selectedFile.sender);
}



void RecievedFilesPage::on_downloadButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
         qDebug() << "Download button: No file selected.";
        return;
    }
    ReceivedFileInfo& selectedFile = receivedFiles[selectedFileIndex];

    if (!selectedFile.isDecrypted) {
        qDebug() << "Download button: File is not yet X3DH processed.";
        QMessageBox::warning(this, "Not Ready", "Please ensure the file is processed (X3DH key derived and metadata decrypted). Download of encrypted content will occur first if needed.");
        return;
    }

    if (selectedFile.actualFileUuid_.isEmpty()) {
        qDebug() << "Download button: Actual file UUID not found. Metadata might not have been decrypted or parsed correctly.";
        QMessageBox::critical(this, "Error", "File UUID not found. Cannot initiate download. Ensure metadata was decrypted.");
        return;
    }



    qDebug() << "Downloading file with actual UUID:" << selectedFile.actualFileUuid_;

    ui->downloadButton->setEnabled(false);
    ui->downloadButton->setText("Downloading...");

    m_receivedFilesManager->downloadEncryptedFile(selectedFile.actualFileUuid_);
    if (selectedFile.decryptedData.isEmpty()) {
        if (!selectedFile.isDownloaded) {
            qDebug() << "Download button: Encrypted content not yet downloaded. Initiating download first.";
            if (selectedFile.actualFileUuid_.isEmpty()) {
                qDebug() << "Download button: Actual file UUID not found. Metadata might not have been decrypted or parsed correctly.";
                QMessageBox::critical(this, "Error", "File UUID not found. Cannot initiate download. Ensure metadata was decrypted.");
            }
            qDebug() << "Downloading file with actual UUID:" << selectedFile.actualFileUuid_;
            ui->downloadButton->setEnabled(false);
            ui->downloadButton->setText("Downloading Encrypted...");
            m_receivedFilesManager->downloadEncryptedFile(selectedFile.actualFileUuid_);
        } else {
             qDebug() << "Download button: File data not decrypted yet or decryption failed. Cannot save.";
             QMessageBox::warning(this, "Not Ready to Save", "File content has been downloaded but is not yet successfully decrypted. Please check status.");
        }
        return;
    }

    // At this point, selectedFile.decryptedData is populated and ready to be saved.
    if (selectedFile.isSavedToDisk) {
        QMessageBox::information(this, "Already Saved", selectedFile.fileName + " has already been saved to disk.");
        return;
    }

    QString suggestedFileName = selectedFile.fileName;
    QString saveFilePath = QFileDialog::getSaveFileName(this, 
                                                        tr("Save File As"), 
                                                        QDir::homePath() + "/" + suggestedFileName,
                                                        tr("All Files (*.*)"));

    if (saveFilePath.isEmpty()) {
        qDebug() << "Save operation cancelled by user.";
        return;
    }

    QFile file(saveFilePath);
    if (!file.open(QIODevice::WriteOnly)) {
        qDebug() << "Failed to open file for writing:" << saveFilePath << "Error:" << file.errorString();
        QMessageBox::critical(this, "Save Error", "Could not save file to the selected location: " + file.errorString());
        return;
    }

    if (file.write(selectedFile.decryptedData) == -1) {
        qDebug() << "Failed to write decrypted data to file:" << saveFilePath << "Error:" << file.errorString();
        QMessageBox::critical(this, "Save Error", "Failed to write data to file: " + file.errorString());
        file.close();
        return;
    }

    file.close();
    qDebug() << "File" << selectedFile.fileName << "saved successfully to" << saveFilePath;
    QMessageBox::information(this, "File Saved", selectedFile.fileName + " has been saved successfully.");
    
    selectedFile.isSavedToDisk = true;
    updateButtonStates();
}


void RecievedFilesPage::on_backButton_clicked()
{
    reject();
    qDebug() << "Back button clicked, closing RecievedFilesPage.";
}


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


void RecievedFilesPage::updateFileInfoDisplay(int index) {
    Q_UNUSED(index);
}

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
             QMessageBox::information(this, "Messages", rootObj["message"].toString()); // Display server message if no messages array
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
        fileInfo.uuid = msgObj.value("message_id").toString();
        fileInfo.sender = msgObj.value("sender_username").toString("Unknown Sender");


        fileInfo.fileName = QString("Encrypted File from %1").arg(fileInfo.sender);

        fileInfo.senderEphemeralPublicKey = QByteArray::fromBase64(msgObj.value("ephemeral_key").toString().toUtf8());
        fileInfo.encryptedMetadata = QByteArray::fromBase64(msgObj.value("encrypted_file_metadata").toString().toUtf8());
        fileInfo.metadataNonce = QByteArray::fromBase64(msgObj.value("encrypted_metadata_nonce").toString().toUtf8());


        fileInfo.fileSize = 0;
        fileInfo.isDecrypted = false;
        fileInfo.isDownloaded = false;
        fileInfo.index = receivedFiles.size();

        receivedFiles.append(fileInfo);
        createFileBox(receivedFiles.last());
    }
    updateButtonStates();
}

void RecievedFilesPage::handleFetchMessagesError(const QString &error)
{
    qDebug() << "Error fetching messages:" << error;
    ui->getFilesButton->setEnabled(true);
    ui->getFilesButton->setText("Get Files");
    QMessageBox::critical(this, "Error Fetching Messages", error);
}


void RecievedFilesPage::handleSenderKeysResponse(const QByteArray &serverResponse)
{
    qDebug() << "Received sender keys response.";
    ui->decryptButton->setText("Processing Keys...");

    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        qWarning() << "handleSenderKeysResponse called with no file selected.";
        ui->decryptButton->setEnabled(true);
        ui->decryptButton->setText("Decrypt File");
        QMessageBox::critical(this, "Error", "No file selected when sender keys response was received.");
        return;
    }
    ReceivedFileInfo& selectedFile = receivedFiles[selectedFileIndex];

    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(serverResponse, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "Failed to parse sender keys JSON:" << parseError.errorString();
        handleFetchSenderKeysError("Failed to parse sender keys: " + parseError.errorString());
        return;
    }
    if (!jsonDoc.isObject()) {
        qWarning() << "Sender keys JSON is not an object.";
        handleFetchSenderKeysError("Invalid sender keys response format (not an object).");
        return;
    }

    QJsonObject keysObj = jsonDoc.object();

    if (keysObj.contains("Public Key") && keysObj["Public Key"].isString()) {
        selectedFile.senderIdentityPublicKeyEd = QByteArray::fromBase64(keysObj["Public Key"].toString().toUtf8());
        qDebug() << "Parsed Sender Identity Key (Public Key).";
    } else {
        handleFetchSenderKeysError("Sender keys JSON missing or invalid 'Public Key'.");
        return;
    }

    
    if (selectedFile.senderIdentityPublicKeyEd.isEmpty()) {
        handleFetchSenderKeysError("Failed to extract sender identity public key.");
        return;
    }

    qDebug() << "Sender keys parsed. Proceeding with KEK retrieval and X3DH derivation for:" << selectedFile.fileName;


    ui->decryptButton->setText("Deriving Session Key...");

        QByteArray kek_qba = SessionManager::getInstance()->getDecryptedKEK();
        if (kek_qba.isEmpty()) {
            QMessageBox::critical(this, "KEK Error", "Failed to retrieve KEK. User session might be invalid. Please log in again.");
            qDebug() << "Failed to retrieve KEK from SessionManager.";
        ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
            return;
        }
        std::vector<unsigned char> kekVector = toStdVector(kek_qba);

    std::string userPackage = "leftovers.project"; 
    std::string userId = "tempUser"; 
    KEKManager kekManager(userPackage, userId);
    QByteArray receiverIdentityPrivEd_qba;
    QByteArray receiverSignedPrekeyPriv_qba;


    try {
        std::vector<unsigned char> receiverIdPrivVec = kekManager.decryptStoredPrivateIdentityKey(kekVector);
        receiverIdentityPrivEd_qba = toQByteArray(receiverIdPrivVec);
        std::vector<unsigned char> receiverSpkPrivVec = kekManager.decryptStoredSignedPreKey(kekVector);
        receiverSignedPrekeyPriv_qba = toQByteArray(receiverSpkPrivVec);

        } catch (const std::runtime_error& e) {
        QMessageBox::critical(this, "Key Retrieval Error", "Failed to retrieve your private keys: " + QString::fromUtf8(e.what()));
        ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
            return;
        }
        
    if (receiverIdentityPrivEd_qba.isEmpty()) {
         QMessageBox::critical(this, "Key Retrieval Error", "Your private identity key is empty after retrieval.");
         ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
            return;
        }

    DecryptionManager decryptionManager;
    selectedFile.derivedDecryptionKey = decryptionManager.deriveFileDecryptionKey(
        selectedFile, // Contains senderEphemeralPublicKey and now senderIdentityPublicKeyEd
        receiverIdentityPrivEd_qba, 
        receiverSignedPrekeyPriv_qba
    );

        if (selectedFile.derivedDecryptionKey.isEmpty()) {
            QMessageBox::critical(this, "Key Derivation Failed", "Could not derive X3DH key for " + selectedFile.fileName);
        ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
            return;
    }
    qDebug() << "Successfully derived X3DH key for:" << selectedFile.fileName;
    ui->decryptButton->setText("Decrypting Metadata...");

    // Metadata Decryption
    selectedFile.decryptedMetadataJsonString = decryptionManager.decryptFileMetadata(
        selectedFile.encryptedMetadata,
        selectedFile.metadataNonce,
        selectedFile.derivedDecryptionKey
    );

    if (selectedFile.decryptedMetadataJsonString.isEmpty()) {
        QMessageBox::warning(this, "Metadata Decryption Failed", 
                             "Could not decrypt metadata for " + selectedFile.fileName + ".");
        qDebug() << "Metadata decryption failed for:" << selectedFile.fileName;
    } else {
        qDebug() << "Successfully decrypted metadata for:" << selectedFile.fileName;
        qDebug() << "Decrypted Metadata JSON:" << selectedFile.decryptedMetadataJsonString;
        QJsonDocument doc = QJsonDocument::fromJson(selectedFile.decryptedMetadataJsonString.toUtf8());
        if (!doc.isNull() && doc.isObject()) {
            QJsonObject jsonObj = doc.object();
            QString actualFilename = jsonObj.value("filename").toString(selectedFile.fileName);
            selectedFile.fileName = actualFilename;
            if (selectedFile.nameLabel) selectedFile.nameLabel->setText("File: " + actualFilename);

            selectedFile.actualFileUuid_ = jsonObj.value("uuid").toString();
            qDebug() << "Stored actual file UUID from metadata:" << selectedFile.actualFileUuid_;

            // Extract DEK, fileNonce, and mimeType
            selectedFile.dek = QByteArray::fromBase64(jsonObj.value("dek").toString().toUtf8());
            selectedFile.fileNonce = QByteArray::fromBase64(jsonObj.value("file_nonce").toString().toUtf8());
            selectedFile.mimeType = jsonObj.value("mime").toString("application/octet-stream"); // Default MIME type

            if (selectedFile.typeLabel) selectedFile.typeLabel->setText("Type: " + selectedFile.mimeType);

            qDebug() << "Parsed DEK, File Nonce, and MIME type from metadata.";
            if (selectedFile.dek.isEmpty()) qDebug() << "Warning: DEK is empty after parsing from metadata.";
            if (selectedFile.fileNonce.isEmpty()) qDebug() << "Warning: File Nonce is empty after parsing from metadata.";

        } else {
            qDebug() << "Failed to parse decrypted metadata as JSON.";
        }
    }

    selectedFile.isDecrypted = !selectedFile.derivedDecryptionKey.isEmpty();
 
    if (selectedFile.isDecrypted) {
         if (selectedFile.displayBox) {
            selectedFile.statusLabel->setText("Status: Decrypted (Key Ready)");
            selectedFile.statusLabel->setStyleSheet("color: #28a745;");
            selectedFile.displayBox->setStyleSheet("QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }");
        }
        QMessageBox::information(this, "Processing Complete", 
                                 selectedFile.fileName + " has been processed. X3DH key is derived. Metadata decryption attempted.");
    } else { // If key derivation failed even after getting sender keys
        QMessageBox::critical(this, "Decryption Failed", "Failed to complete decryption process for " + selectedFile.fileName);
    }
    
    ui->decryptButton->setEnabled(!selectedFile.isDecrypted);
    ui->decryptButton->setText("Decrypt File");
    updateButtonStates();
}

void RecievedFilesPage::handleFetchSenderKeysError(const QString &error)
{
    qDebug() << "Error fetching sender keys:" << error;
    // Only re-enable if a file is still selected and not yet successfully processed
    if (selectedFileIndex >= 0 && selectedFileIndex < receivedFiles.size() && !receivedFiles[selectedFileIndex].isDecrypted) {
        ui->decryptButton->setEnabled(true); 
    }
    ui->decryptButton->setText("Decrypt File");
    QMessageBox::critical(this, "Error Fetching Sender Keys", error);
}


void RecievedFilesPage::handleFileDownloadSuccess(const QByteArray &encryptedFileBytes, const QString &file_uuid_ref)
{
    qDebug() << "Successfully downloaded encrypted file content for UUID_ref:" << file_uuid_ref;
    ui->downloadButton->setText("Download File");

    // Find the corresponding file in our list
    int fileIdx = -1;
    for (int i = 0; i < receivedFiles.size(); ++i) {
        if (receivedFiles[i].actualFileUuid_ == file_uuid_ref) {
            fileIdx = i;
            break;
        }
    }

    if (fileIdx == -1) {
        qWarning() << "Could not find file with UUID" << file_uuid_ref << "in the list after download.";
        // Re-enable button if it was the selected one
        if (selectedFileIndex >=0 && selectedFileIndex < receivedFiles.size() && receivedFiles[selectedFileIndex].actualFileUuid_ == file_uuid_ref) {
            ui->downloadButton->setEnabled(true);
        }
        QMessageBox::critical(this, "Download Error", "Internal error: Downloaded file context lost.");
        return;
    }

    ReceivedFileInfo& targetFile = receivedFiles[fileIdx];
    targetFile.encryptedData = encryptedFileBytes;
    targetFile.isDownloaded = true;

    qDebug() << "Stored encrypted data for" << targetFile.fileName << "Size:" << targetFile.encryptedData.size();

    // Attempt to decrypt the file data immediately after download
    if (!targetFile.dek.isEmpty() && !targetFile.fileNonce.isEmpty()) {
        DecryptionManager decryptionManager;
        targetFile.decryptedData = decryptionManager.decryptFileData(
            targetFile.encryptedData,
            targetFile.dek,
            targetFile.fileNonce
        );

        if (!targetFile.decryptedData.isEmpty()) {
            qDebug() << "Successfully decrypted file data for:" << targetFile.fileName << "Decrypted size:" << targetFile.decryptedData.size();
            QMessageBox::information(this, "Decryption Successful",
                                     targetFile.fileName + " has been successfully decrypted and is ready to be saved.");
            if (targetFile.statusLabel) {
                targetFile.statusLabel->setText("Status: Decrypted (Ready to Save)");
            }
            if (targetFile.displayBox && selectedFileIndex == fileIdx) { 
                targetFile.displayBox->setStyleSheet("QFrame { background-color: #bbdefb; border: 2px solid #007bff; border-radius: 4px; }");
            }
        } else {
            qDebug() << "Failed to decrypt file data for:" << targetFile.fileName;
            QMessageBox::warning(this, "Decryption Failed",
                                 "Could not decrypt the content of " + targetFile.fileName + ". The file might be corrupted or the key/nonce is incorrect.");
            if (targetFile.statusLabel) {
                targetFile.statusLabel->setText("Status: Downloaded (Decryption Failed)");
            }
        }
    } else {
        qWarning() << "Cannot decrypt file data: DEK or file nonce is missing for" << targetFile.fileName;
        QMessageBox::information(this, "Download Complete",
                                 "Encrypted content for " + targetFile.fileName + " downloaded. Metadata for decryption seems incomplete.");
        if (targetFile.statusLabel) {
            targetFile.statusLabel->setText("Status: Downloaded (Encrypted - Meta Missing)");
        }
    }


    updateButtonStates();
}


void RecievedFilesPage::handleFileDownloadError(const QString &error, const QString &file_uuid_ref)
{
    qDebug() << "Error downloading file for UUID_ref:" << file_uuid_ref << ":" << error;
    QMessageBox::critical(this, "Download Failed", "Failed to download file (" + file_uuid_ref + "): " + error);
    
    // Re-enable download button if it was the selected one that failed
    if (selectedFileIndex >= 0 && selectedFileIndex < receivedFiles.size()) {
        if (receivedFiles[selectedFileIndex].actualFileUuid_ == file_uuid_ref) {
            ui->downloadButton->setEnabled(true); 
        }
    }
    ui->downloadButton->setText("Download File");
    updateButtonStates();
} 