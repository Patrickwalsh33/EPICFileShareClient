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
    // Setup for ReceivedFilesManager - Sender Keys
    connect(m_receivedFilesManager, &ReceivedFilesManager::senderKeysReceived,
            this, &RecievedFilesPage::handleSenderKeysResponse);
    connect(m_receivedFilesManager, &ReceivedFilesManager::fetchSenderKeysFailed,
            this, &RecievedFilesPage::handleFetchSenderKeysError);
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

    // Request sender's keys. The rest of the decryption logic will be in handleSenderKeysResponse
    m_receivedFilesManager->requestSenderKeys(selectedFile.sender);
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

// New slot to handle response for sender public keys
void RecievedFilesPage::handleSenderKeysResponse(const QByteArray &serverResponse)
{
    qDebug() << "Received sender keys response.";
    ui->decryptButton->setText("Processing Keys..."); // Update UI feedback

    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size()) {
        qWarning() << "handleSenderKeysResponse called with no file selected.";
        ui->decryptButton->setEnabled(true); // Re-enable on error
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
    // Assuming server returns structure like: {"Public Key": "base64IK", "Public Pre Key": "base64SPK", "Pre Key Signature": "base64Sig"}
    // This matches the keys needed by X3DH_sender_derive_shared_secret (as receiver)
    // and what uploadManager::handleRecipientKeysResponse parses.
    // For X3DH as receiver, we need sender's IDKey_pub, SPK_pub, SPK_sig, and EK_pub.
    // EK_pub is already in selectedFile.senderEphemeralPublicKey from the message.

    if (keysObj.contains("Public Key") && keysObj["Public Key"].isString()) {
        selectedFile.senderIdentityPublicKeyEd = QByteArray::fromBase64(keysObj["Public Key"].toString().toUtf8());
        qDebug() << "Parsed Sender Identity Key (Public Key).";
    } else {
        handleFetchSenderKeysError("Sender keys JSON missing or invalid 'Public Key'.");
        return;
    }

    // Note: The X3DH receiver function (x3dh_receiver_derive_shared_secret) will actually expect:
    // - Our own identity private key (IDKey_priv_B)
    // - Our own signed prekey private key (SPKey_priv_B)
    // - Our own one-time prekey private key (OPKey_priv_B) - if used
    // - Sender's identity public key (IDKey_pub_A) -> This is senderIdentityPublicKeyEd
    // - Sender's ephemeral public key (EKey_pub_A) -> This is senderEphemeralPublicKey

    // The bundle from /users/ usually contains the sender's signed prekey and its signature too,
    // but these are primarily for the *sender* to use when *they* initiate X3DH with *us*.
    // For *us* (receiver) deriving the shared secret with a message *they* sent, 
    // we primarily need *their* IDKey_pub and *their* EKey_pub.
    // The DecryptionManager::deriveFileDecryptionKey currently takes sender's ID key and sender's Ephemeral key.
    // Let's ensure DecryptionManager expects the correct public keys.
    // The provided DecryptionManager::deriveFileDecryptionKey seems to already expect this.
    
    if (selectedFile.senderIdentityPublicKeyEd.isEmpty()) {
        handleFetchSenderKeysError("Failed to extract sender identity public key.");
        return;
    }

    qDebug() << "Sender keys parsed. Proceeding with KEK retrieval and X3DH derivation for:" << selectedFile.fileName;

    // --- Now, the original decryption logic from on_decryptButton_clicked --- 
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
    QByteArray receiverSignedPrekeyPriv_qba; // May not be strictly needed by X3DH receiver side if OPK is used
                                         // but good to have if full bundle interaction is assumed by KEKManager or local key storage logic

    try {
        std::vector<unsigned char> receiverIdPrivVec = kekManager.decryptStoredPrivateIdentityKey(kekVector);
        receiverIdentityPrivEd_qba = toQByteArray(receiverIdPrivVec);
        // For X3DH receiver, we might also need our signed prekey private or one-time prekey private.
        // Assuming DecryptionManager internally handles which of our own private keys to use based on message type (e.g. if it has OPK_ID)
        // For now, we fetch SPK_priv as it was in original logic.
        std::vector<unsigned char> receiverSpkPrivVec = kekManager.decryptStoredSignedPreKey(kekVector);
        receiverSignedPrekeyPriv_qba = toQByteArray(receiverSpkPrivVec);

    } catch (const std::runtime_error& e) {
        QMessageBox::critical(this, "Key Retrieval Error", "Failed to retrieve your private keys: " + QString::fromUtf8(e.what()));
        ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
        return;
    }
        
    if (receiverIdentityPrivEd_qba.isEmpty()) { // Only receiver ID priv key is absolutely essential for receiver X3DH
         QMessageBox::critical(this, "Key Retrieval Error", "Your private identity key is empty after retrieval.");
         ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
        return;
    }

    DecryptionManager decryptionManager;
    selectedFile.derivedDecryptionKey = decryptionManager.deriveFileDecryptionKey(
        selectedFile, // Contains senderEphemeralPublicKey and now senderIdentityPublicKeyEd
        receiverIdentityPrivEd_qba, 
        receiverSignedPrekeyPriv_qba // Pass this, DecryptionManager might choose to use it or an OPK if applicable
    );

    if (selectedFile.derivedDecryptionKey.isEmpty()) {
        QMessageBox::critical(this, "Key Derivation Failed", "Could not derive X3DH key for " + selectedFile.fileName);
        ui->decryptButton->setEnabled(true); ui->decryptButton->setText("Decrypt File");
        return;
    }
    qDebug() << "Successfully derived X3DH key for:" << selectedFile.fileName;
    ui->decryptButton->setText("Decrypting Metadata...");

    // --- Metadata Decryption ---
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
            QString actualFilename = jsonObj.value("filename").toString(selectedFile.fileName); // Use original if not in metadata
            if (selectedFile.nameLabel) selectedFile.nameLabel->setText("File: " + actualFilename);
            // Potentially update selectedFile.fileName itself if needed elsewhere
        } else {
            qDebug() << "Failed to parse decrypted metadata as JSON.";
        }
    }

    selectedFile.isDecrypted = !selectedFile.derivedDecryptionKey.isEmpty();
 
    if (selectedFile.isDecrypted) {
         if (selectedFile.displayBox) {
            selectedFile.statusLabel->setText("Status: Decrypted (Key Ready)");
            selectedFile.statusLabel->setStyleSheet("color: #28a745;");
            selectedFile.displayBox->setStyleSheet("QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }"); // Highlight selected and decrypted
        }
        QMessageBox::information(this, "Processing Complete", 
                                 selectedFile.fileName + " has been processed. X3DH key is derived. Metadata decryption attempted.");
    } else { // If key derivation failed even after getting sender keys
        QMessageBox::critical(this, "Decryption Failed", "Failed to complete decryption process for " + selectedFile.fileName);
    }
    
    ui->decryptButton->setEnabled(!selectedFile.isDecrypted); // Disable if successful
    ui->decryptButton->setText("Decrypt File");
    updateButtonStates(); // This will correctly enable/disable download button
}

// New slot to handle errors from sender key fetch
void RecievedFilesPage::handleFetchSenderKeysError(const QString &error)
{
    qDebug() << "Error fetching sender keys:" << error;
    if (selectedFileIndex >= 0 && selectedFileIndex < receivedFiles.size()) {
        // Only re-enable if a file is still logically selected
        ui->decryptButton->setEnabled(true); 
    }
    ui->decryptButton->setText("Decrypt File");
    QMessageBox::critical(this, "Error Fetching Sender Keys", error);
}