#include "uploadpage.h"
#include "ui_uploadpage.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QFile>
#include <QDebug>
#include "../../crypto/crypto_utils.h"
#include "../../X3DH/X3DH_shared.h"
#include <iostream>
#include "../../key_management/X3DHKeys/EphemeralKeyPair.h"
#include "../../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/KEKManager.h"
#include "../SessionManager/SessionManager.h"
#include <QUuid>
#include <QMimeDatabase>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLineEdit>
#include <QJsonParseError>


std::string userPackage = "leftovers.project";
std::string userId = "tempUser";

KEKManager kekManager(userPackage, userId);

UploadPage::UploadPage(QWidget *parent) :
        QDialog(parent),
        ui(new Ui::UploadPage),
        uploader(new uploadManager(this)),
        selectedFileIndex(static_cast<size_t>(-1)) {
    ui->setupUi(this);

    // Connect usernameLineEdit
    connect(ui->usernameLineEdit, &QLineEdit::textChanged, this, &UploadPage::onUsernameChanged);

    // Connect uploader signals
    connect(uploader, &uploadManager::recipientKeysReceived, this, &UploadPage::handleRecipientKeysResponse);
    // You might also want to connect recipientKeysFailed to a slot to handle errors
    // connect(uploader, &uploadManager::recipientKeysFailed, this, &UploadPage::handleRecipientKeysError); 

    // Replace the standard buttons with HoverButton
    HoverButton* selectFileBtn = new HoverButton(this);
    selectFileBtn->setGeometry(ui->selectFileButton->geometry());
    selectFileBtn->setText(ui->selectFileButton->text());
    selectFileBtn->setStyleSheet(ui->selectFileButton->styleSheet());
    selectFileBtn->setObjectName("selectFileButton");
    delete ui->selectFileButton;
    ui->selectFileButton = selectFileBtn;
    connect(ui->selectFileButton, &QPushButton::clicked, this, &UploadPage::on_selectFileButton_clicked);

    HoverButton* encryptBtn = new HoverButton(this);
    encryptBtn->setGeometry(ui->encryptButton->geometry());
    encryptBtn->setText(ui->encryptButton->text());
    encryptBtn->setStyleSheet(ui->encryptButton->styleSheet());
    encryptBtn->setObjectName("encryptButton");
    delete ui->encryptButton;
    ui->encryptButton = encryptBtn;
    connect(ui->encryptButton, &QPushButton::clicked, this, &UploadPage::on_encryptButton_clicked);

    HoverButton* uploadBtn = new HoverButton(this);
    uploadBtn->setGeometry(ui->uploadButton->geometry());
    uploadBtn->setText(ui->uploadButton->text());
    uploadBtn->setStyleSheet(ui->uploadButton->styleSheet());
    uploadBtn->setObjectName("uploadButton");
    delete ui->uploadButton;
    ui->uploadButton = uploadBtn;
    connect(ui->uploadButton, &QPushButton::clicked, this, &UploadPage::on_uploadButton_clicked);

    HoverButton* backBtn = new HoverButton(this);
    backBtn->setGeometry(ui->backButton->geometry());
    backBtn->setText(ui->backButton->text());
    backBtn->setStyleSheet(ui->backButton->styleSheet());
    backBtn->setObjectName("backButton");
    delete ui->backButton;
    ui->backButton = backBtn;
    connect(ui->backButton, &QPushButton::clicked, this, &UploadPage::on_backButton_clicked);

    ui->uploadButton->setEnabled(false);
    ui->encryptButton->setEnabled(true);
    ui->uploadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
    ui->encryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");

    uploader->setServerUrl("https://leftovers.gobbler.info");

    connect(uploader, &uploadManager::uploadSucceeded, this, [=](const QByteArray &serverResponse) {
        qDebug() << "UploadPage received uploadSucceeded with server response:" << serverResponse;
        QJsonParseError parseError;
        QJsonDocument jsonDoc = QJsonDocument::fromJson(serverResponse, &parseError);
        if (parseError.error == QJsonParseError::NoError && jsonDoc.isObject()) {
            QJsonObject jsonObj = jsonDoc.object();
            QString message = jsonObj.value("message").toString("File uploaded successfully.");
            QString clientUuid = jsonObj.value("client_uuid").toString();
            int fileIdInDb = jsonObj.value("file_id_in_db").toInt(-1);
            qDebug() << "Server message:" << message << "Client UUID:" << clientUuid << "DB File ID:" << fileIdInDb;
            QMessageBox::information(this, "Upload Success", message);
        } else {
            qDebug() << "Failed to parse successful upload response or not a JSON object. Raw response:" << serverResponse;
            QMessageBox::information(this, "Upload Success", "File uploaded, but server response was not in expected JSON format.");
        }
        // Potentially reset UI elements or navigate away
        updateButtonStates(); // Re-evaluate button states
    });

    connect(uploader, &uploadManager::uploadFailed, this, [=](const QString &error) {
        QMessageBox::critical(this, "Upload Failed", "Error uploading file: " + error);
    });
}

UploadPage::~UploadPage() {
    delete ui;
}

void UploadPage::on_selectFileButton_clicked() {
    QString fileName = QFileDialog::getOpenFileName(this, "Select File to Upload", QDir::homePath(), "All Files (*.*)");
    QMimeDatabase db;

    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "File Error", "Failed to open selected file.");
            return;
        }

        QByteArray fileData = file.readAll();
        file.close();

        // Construct FileInfo struct
        FileInfo newFile;
        newFile.path = fileName;
        newFile.originalData = fileData;
        newFile.isEncrypted = false;
        newFile.uuid = QUuid::createUuid().toString(QUuid::WithoutBraces);
        newFile.dek = DataEncryptionKey().getKey();
        newFile.mimeType = db.mimeTypeForFile(fileName).name();
        QFileInfo fi(fileName);
        newFile.fileName = fi.fileName();
        newFile.index = files.size();

        // Add to file list and update UI
        files.push_back(newFile);              // Add to internal list
        createFileBox(files.back());           // Create UI box for file
        updateFileInfo(files.size() - 1);      // Update displayed info
    }
}

void UploadPage::createFileBox(FileInfo& fileInfo) {
    ClickableFrame* box = new ClickableFrame(ui->scrollAreaWidgetContents);
    box->setObjectName("fileBox");
    box->setMinimumHeight(80);
    box->setStyleSheet("QFrame#fileBox { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }");
    box->setCursor(Qt::PointingHandCursor);

    QVBoxLayout* boxLayout = new QVBoxLayout(box);
    boxLayout->setContentsMargins(10, 5, 10, 5);
    boxLayout->setSpacing(2);

    fileInfo.nameLabel = new QLabel(QFileInfo(fileInfo.path).fileName(), box);
    fileInfo.nameLabel->setStyleSheet("font-weight: bold;");
    fileInfo.sizeLabel = new QLabel(formatFileSize(fileInfo.originalData.size()), box);
    fileInfo.typeLabel = new QLabel(QFileInfo(fileInfo.path).suffix().toUpper(), box);
    fileInfo.statusLabel = new QLabel("Not Encrypted", box);
    fileInfo.statusLabel->setStyleSheet("color: #666;");

    boxLayout->addWidget(fileInfo.nameLabel);
    boxLayout->addWidget(fileInfo.sizeLabel);
    boxLayout->addWidget(fileInfo.typeLabel);
    boxLayout->addWidget(fileInfo.statusLabel);

    fileInfo.displayBox = box;

    // Insert at the top of the scroll area
    QVBoxLayout* scrollLayout = qobject_cast<QVBoxLayout*>(ui->scrollAreaWidgetContents->layout());
    if (scrollLayout) {
        scrollLayout->insertWidget(0, box);
    }

    // Connect the clicked signal using the index
    connect(box, &ClickableFrame::clicked, this, [this, index = fileInfo.index]() {
        qDebug() << "File box clicked, index:" << index;
        onFileBoxClicked(index);
    });
}

void UploadPage::onFileBoxClicked(size_t index) {
    if (index >= files.size()) {
        qDebug() << "Invalid file index:" << index;
        return;
    }

    qDebug() << "Processing click for file index:" << index;
    
    // Reset all boxes to default style
    for (const auto& file : files) {
        if (file.displayBox) {
            file.displayBox->setStyleSheet("QFrame#fileBox { background-color: #f0f0f0; border: 1px solid #ccc; border-radius: 4px; }");
        }
    }

    // Highlight selected box
    if (files[index].displayBox) {
        files[index].displayBox->setStyleSheet("QFrame#fileBox { background-color: #e0e0e0; border: 2px solid #007bff; border-radius: 4px; }");
    }

    selectedFileIndex = index;
    updateButtonStates();
    updateFileInfo(index);
}

void UploadPage::updateButtonStates() {
    if (selectedFileIndex >= files.size()) {
        ui->encryptButton->setEnabled(false);
        ui->uploadButton->setEnabled(false);
        ui->encryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
        ui->uploadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
        return;
    }

    const auto& selectedFile = files[selectedFileIndex];
    if (!selectedFile.isEncrypted) {
        ui->encryptButton->setEnabled(true);
        ui->uploadButton->setEnabled(false);
        ui->encryptButton->setStyleSheet("color: white; background-color: #2196F3; border: none; border-radius: 5px; font-size: 14px;");
        ui->uploadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
    } else {
        ui->encryptButton->setEnabled(false);
        ui->uploadButton->setEnabled(true);
        ui->encryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
        ui->uploadButton->setStyleSheet("color: white; background-color: #2196F3; border: none; border-radius: 5px; font-size: 14px;");
    }
}

void printSharedSecret(const unsigned char* secret, size_t length) {
    std::cout << "Shared Secret: ";
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(secret[i]);
    }
    std::cout << std::dec << std::endl;
}

void UploadPage::onUsernameChanged(const QString &text) {
    currentUsername = text;
    qDebug() << "Username changed to:" << currentUsername;
}

void UploadPage::handleRecipientKeysResponse(const QByteArray &data) {
    qDebug() << "UploadPage received recipientKeysReceived signal with data:" << data.left(200); 



    QJsonParseError parseError;
    QJsonDocument jsonDoc = QJsonDocument::fromJson(data, &parseError);

    if (parseError.error != QJsonParseError::NoError) {
        qWarning() << "Failed to parse recipient keys JSON:" << parseError.errorString();

        return;
    }

    if (!jsonDoc.isObject()) {
        qWarning() << "Recipient keys JSON is not an object.";
        return;
    }

    QJsonObject jsonObj = jsonDoc.object();

    // Corrected keys to match server JSON response
    if (jsonObj.contains("Public Key") && jsonObj["Public Key"].isString()) {
        this->recipientIdentityKey_ = jsonObj["Public Key"].toString();
        qDebug() << "Parsed recipientIdentityKey_ (Public Key):" << this->recipientIdentityKey_;
    } else {
        qWarning() << "Recipient keys JSON missing or invalid 'Public Key'";
    }

    if (jsonObj.contains("Public Pre Key") && jsonObj["Public Pre Key"].isString()) {
        this->recipientSignedPreKey_ = jsonObj["Public Pre Key"].toString();
        qDebug() << "Parsed recipientSignedPreKey_ (Public Pre Key):" << this->recipientSignedPreKey_;
    } else {
        qWarning() << "Recipient keys JSON missing or invalid 'Public Pre Key'";
    }

    if (jsonObj.contains("Pre Key Signature") && jsonObj["Pre Key Signature"].isString()) {
        this->recipientPreKeySignature_ = jsonObj["Pre Key Signature"].toString();
        qDebug() << "Parsed recipientPreKeySignature_ (Pre Key Signature):" << this->recipientPreKeySignature_;
    } else {
        qWarning() << "Recipient keys JSON missing or invalid 'Pre Key Signature'";
    }

    // Check if all keys were successfully parsed
    if (!this->recipientIdentityKey_.isEmpty() && 
        !this->recipientSignedPreKey_.isEmpty() && 
        !this->recipientPreKeySignature_.isEmpty()) {
        
        qDebug() << "All recipient keys successfully parsed. Proceeding with encryption.";
        // Restore button text before proceeding or after encryption is fully done in proceedWithEncryption
        ui->encryptButton->setText("Encrypt File"); 

        
        proceedWithEncryption(); // Call proceedWithEncryption now that keys are ready
    } else {
        qCritical() << "One or more recipient keys could not be parsed. Encryption aborted.";
        QMessageBox::critical(this, "Encryption Error", "Could not retrieve all necessary recipient keys. Please check the username or try again.");
        // Restore UI state since we are not proceeding
        ui->encryptButton->setEnabled(true);
        ui->encryptButton->setText("Encrypt File");
    }
}

void UploadPage::on_encryptButton_clicked()
{
    // Ensure a username is entered
    if (this->currentUsername.isEmpty()) {
        QMessageBox::warning(this, "Input Error", "Please enter a recipient username.");
        return;
    }
    qDebug() << "Encrypt button clicked for recipient:" << this->currentUsername;


    ui->encryptButton->setEnabled(false);
    ui->encryptButton->setText("Fetching keys...");


    // Call requestRecipientKeys
    uploader->requestRecipientKeys(this->currentUsername);


}

void UploadPage::proceedWithEncryption(){
    qDebug() << "Proceeding with encryption for selected file index:" << selectedFileIndex;
    if (selectedFileIndex >= files.size() || files[selectedFileIndex].isEncrypted) {
        return;
    }

    auto& selectedFile = files[selectedFileIndex];
    unsigned long long fileCiphertext_len;
    std::vector<unsigned char> fileCiphertext(selectedFile.originalData.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    std::vector<unsigned char> fileNonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);


    //encrypt the file data with the dek
    encrypt_with_chacha20(
            reinterpret_cast<const unsigned char*>(selectedFile.originalData.constData()),
            selectedFile.originalData.size(),
            selectedFile.dek.data(),
            fileCiphertext.data(),
            &fileCiphertext_len,
            fileNonce.data()
    );


    EphemeralKeyPair ephemeralKeyPair;
    const unsigned char* senderEphemeralPrivateKey = ephemeralKeyPair.getPrivateKey().data();
    const unsigned char* senderEphemeralPublicKey  = ephemeralKeyPair.getPublicKey().data();

    // Get KEK from SessionManager
    QByteArray kek = SessionManager::getInstance()->getDecryptedKEK();
    if (kek.isEmpty()) {
        QMessageBox::critical(this, "Encryption Error", "User session is invalid or KEK not found. Please log in again.");
        return;
    }

    std::vector<unsigned char> kekVector(
            reinterpret_cast<const unsigned char*>(kek.constData()),
            reinterpret_cast<const unsigned char*>(kek.constData()) + kek.size()
    );

    std::vector<unsigned char> SenderPrivIDKey = kekManager.decryptStoredPrivateIdentityKey(kekVector);
    const unsigned char* senderId = SenderPrivIDKey.data();

    QByteArray identityKeyBytes = QByteArray::fromBase64(this->recipientIdentityKey_.toUtf8());
    QByteArray signedPreKeyBytes = QByteArray::fromBase64(this->recipientSignedPreKey_.toUtf8());
    QByteArray preKeySigBytes = QByteArray::fromBase64(this->recipientPreKeySignature_.toUtf8());

    if (identityKeyBytes.size() != crypto_sign_PUBLICKEYBYTES ||
        signedPreKeyBytes.size() != crypto_scalarmult_BYTES ||
        preKeySigBytes.size() != crypto_sign_BYTES) {
        qCritical() << "Key size mismatch! Aborting.";
        return;
    }


    unsigned char sharedSecret[crypto_generichash_BYTES]; // 32 bytes
    bool success = x3dh_sender_derive_shared_secret(
            sharedSecret,
            sizeof(sharedSecret),
            senderEphemeralPrivateKey,
            senderId,
            reinterpret_cast<const unsigned char*>(identityKeyBytes.constData()),
            reinterpret_cast<const unsigned char*>(signedPreKeyBytes.constData()),
            reinterpret_cast<const unsigned char*>(preKeySigBytes.constData()));

    if (success) {
        printSharedSecret(sharedSecret, crypto_generichash_BYTES);
    }

    unsigned char derivedKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES]; // 32 bytes
    const char context[8] = "X3DHKEY";
    uint64_t subkey_id = 1;

    bool derived = derive_key_from_shared_secret(
            sharedSecret,
            derivedKey,
            context,
            subkey_id
    );

    if (!derived) {
        QMessageBox::critical(this, "Key Derivation Error", "Failed to derive key from shared secret.");
        return;
    }

    //get file metadata into json object
    QJsonObject metadataJson;
    metadataJson["uuid"] = selectedFile.uuid;
    QString base64Dek = QByteArray(reinterpret_cast<const char*>(selectedFile.dek.data()), selectedFile.dek.size()).toBase64();
    metadataJson["dek"] = base64Dek;
    QString base64FileNonce = QByteArray(reinterpret_cast<const char*>(fileNonce.data()), fileNonce.size()).toBase64();
    metadataJson["file_nonce"] = base64FileNonce;
    metadataJson["filename"] = selectedFile.fileName;
    metadataJson["mime"] = selectedFile.mimeType;

// serialize to string
    QJsonDocument doc(metadataJson);
    QString jsonString = doc.toJson(QJsonDocument::Compact);

    std::cout << "File Metadata JSON: " << jsonString.toStdString() << std::endl;


// Encrypt the file metadata using the derived key
    QByteArray jsonData = jsonString.toUtf8();

    std::vector<unsigned char> metaNonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(metaNonce.data(), metaNonce.size());

    std::vector<unsigned char> encryptedMetadata(jsonData.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long encryptedMetadataLen = 0;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            encryptedMetadata.data(), &encryptedMetadataLen,
            reinterpret_cast<const unsigned char*>(jsonData.constData()), jsonData.size(),
            nullptr, 0,  // no associated data
            nullptr,
            metaNonce.data(),
            derivedKey
    ) != 0) {
        QMessageBox::critical(this, "Encryption Error", "Failed to encrypt file metadata.");
        return;
    }

    std::cout << "[X3DH] File metadata successfully encrypted." << std::endl;



    selectedFile.encryptedData = QByteArray(reinterpret_cast<const char*>(fileCiphertext.data()), fileCiphertext_len);
    selectedFile.encryptedFileNonce = QByteArray(reinterpret_cast<const char*>(fileNonce.data()), fileNonce.size());
    selectedFile.encryptedMetadata = QByteArray(reinterpret_cast<const char*>(encryptedMetadata.data()), encryptedMetadataLen);
    selectedFile.metadataNonce = QByteArray(reinterpret_cast<const char*>(metaNonce.data()), metaNonce.size());
    selectedFile.isEncrypted = true;

    selectedFile.statusLabel->setText("Status: Encrypted and ready for upload");
    selectedFile.displayBox->setStyleSheet("QFrame#fileBox { background-color: #e8f5e9; border: 2px solid #4CAF50; border-radius: 4px; }");
    
    updateButtonStates();

    QMessageBox msgBox(this);
    msgBox.setWindowTitle("Encryption Complete");
    msgBox.setText("File has been encrypted and is ready for upload.");
    msgBox.setStyleSheet("QMessageBox { background-color: #f0f0f0; }"
                        "QMessageBox QLabel { color: #333333; font-size: 12px; }"
                        "QPushButton { background-color: #2196F3; color: white; border: none; padding: 5px 15px; border-radius: 3px; }"
                        "QPushButton:hover { background-color: #1976D2; }");
    msgBox.exec();
}


void UploadPage::on_uploadButton_clicked() {
    if (selectedFileIndex >= files.size() || !files[selectedFileIndex].isEncrypted) {
        QMessageBox::warning(this, "Upload Error", "Please select an encrypted file to upload.");
        return;
    }

    const auto& selectedFile = files[selectedFileIndex];
    
    qDebug() << "Calling uploader->uploadFile with UUID:" << selectedFile.uuid << "and Filename:" << selectedFile.fileName;
    // Pass the encrypted data, file UUID, and original filename
    uploader->uploadFile(selectedFile.encryptedData, selectedFile.uuid, selectedFile.fileName);
}

void UploadPage::on_backButton_clicked() {
    reject(); //when reject is called it returns to whatever code called it
    qDebug() << "Back button clicked";
}

void UploadPage::updateFileInfo(size_t index) {
    if (index >= files.size()) {
        return;
    }

    const auto& fileInfo = files[index];
    QFileInfo qFileInfo(fileInfo.path);
    fileInfo.nameLabel->setText("File: " + qFileInfo.fileName());
    fileInfo.sizeLabel->setText("Size: " + formatFileSize(qFileInfo.size()));
    fileInfo.typeLabel->setText("Type: " + (qFileInfo.suffix().isEmpty() ? "Unknown" : qFileInfo.suffix().toUpper() + " File"));
    fileInfo.statusLabel->setText(fileInfo.isEncrypted ? "Status: Encrypted and ready for upload" : "Status: Not encrypted");
}

QString UploadPage::formatFileSize(qint64 size) {
    if (size < 1024)
        return QString("%1 bytes").arg(size);
    else if (size < 1024 * 1024)
        return QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    else if (size < 1024 * 1024 * 1024)
        return QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    else
        return QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
}
