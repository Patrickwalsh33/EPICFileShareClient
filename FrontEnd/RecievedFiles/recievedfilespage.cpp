#include "recievedfilespage.h"
#include "ui_recievedfilespage.h"
#include "../HomePage/homepage.h"
#include "../../Backend/Decryption/DecryptionManager.h"
#include <QDebug>
#include <QMessageBox>
#include <QVBoxLayout>
#include <QEvent>
#include <QMouseEvent>
#include <sodium.h>

// Key Management Includes
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/X3DHKeys/EphemeralKeyPair.h"
#include "../../key_management/X3DHKeys/SignedPreKeyPair.h"

// Helper function to convert std::vector<unsigned char> to QByteArray
QByteArray toQByteArray(const std::vector<unsigned char>& vec) {
    return QByteArray(reinterpret_cast<const char*>(vec.data()), vec.size());
}

RecievedFilesPage::RecievedFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RecievedFilesPage)
{
    ui->setupUi(this);
    // Initialize sodium if it hasn't been already (though DecryptionManager also does it)
    if (sodium_init() < 0) {
        qCritical() << "Failed to initialize libsodium in RecievedFilesPage";
        // Potentially disable functionality or show an error
    }

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

// Declare static keys for the sender so they are consistent for all dummy files
// In a real scenario, these would be specific to each sender/message instance.
static IdentityKeyPair testSenderIdentityKeys;
static EphemeralKeyPair testSenderEphemeralKeys;

void RecievedFilesPage::on_getFilesButton_clicked()
{
    qDebug() << "Get Files button clicked. Populating with VALID dummy files and keys.";
    while (QLayoutItem* item = ui->scrollAreaWidgetContents->layout()->takeAt(0)) {
        if (item->widget()) {
            item->widget()->removeEventFilter(this);
            delete item->widget();
        }
        delete item;
    }
    receivedFiles.clear();
    selectedFileIndex = -1;

    // Use the statically generated sender keys
    QByteArray senderEphemeralPub = toQByteArray(testSenderEphemeralKeys.getPublicKey());
    QByteArray senderIdentityPubEd = toQByteArray(testSenderIdentityKeys.getPublicKey());

    qDebug() << "Test Sender Ephemeral Public Key (first 5 bytes):" << senderEphemeralPub.left(5).toHex();
    qDebug() << "Test Sender Identity Public Key (first 5 bytes):" << senderIdentityPubEd.left(5).toHex();

    ReceivedFileInfo file1;
    file1.fileName = "Document1.enc";
    file1.sender = "UserA";
    file1.fileSize = 1024 * 5;
    file1.isDecrypted = false;
    file1.uuid = "uuid1";
    file1.senderEphemeralPublicKey = senderEphemeralPub;
    file1.senderIdentityPublicKeyEd = senderIdentityPubEd;
    file1.index = receivedFiles.size();
    receivedFiles.append(file1);
    createFileBox(receivedFiles.last());

    // ... (file2 and file3 setup similar to file1, using the same sender keys for test)
    ReceivedFileInfo file2;
    file2.fileName = "Picture.jpg.enc";
    file2.sender = "UserB";
    file2.fileSize = 1024 * 1024 * 2;
    file2.isDecrypted = false;
    file2.uuid = "uuid2";
    file2.senderEphemeralPublicKey = senderEphemeralPub;
    file2.senderIdentityPublicKeyEd = senderIdentityPubEd;
    file2.index = receivedFiles.size();
    receivedFiles.append(file2);
    createFileBox(receivedFiles.last());

    ReceivedFileInfo file3;
    file3.fileName = "Archive.zip.enc";
    file3.sender = "UserC";
    file3.fileSize = 1024 * 1024 * 15;
    file3.isDecrypted = false;
    file3.uuid = "uuid3";
    file3.senderEphemeralPublicKey = senderEphemeralPub;
    file3.senderIdentityPublicKeyEd = senderIdentityPubEd;
    file3.index = receivedFiles.size();
    receivedFiles.append(file3);
    createFileBox(receivedFiles.last());
    
    updateButtonStates();
}

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
    
    QLabel* sizeLabel = new QLabel("Size: " + formatFileSize(fileInfo.fileSize), box);
    sizeLabel->setStyleSheet("font-size: 12px; color: #555;");

    fileInfo.statusLabel = new QLabel(fileInfo.isDecrypted ? "Status: Decrypted" : "Status: Encrypted", box);
    fileInfo.statusLabel->setStyleSheet(fileInfo.isDecrypted ? "color: #28a745;" : "color: #dc3545;");

    boxLayout->addWidget(fileInfo.nameLabel);
    boxLayout->addWidget(fileInfo.senderLabel);
    boxLayout->addWidget(sizeLabel);
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

// Declare static keys for the receiver for consistent testing
static IdentityKeyPair testReceiverIdentityKeys;
// The signed prekey depends on the identity key, so it must be created after.
// We can initialize it as a pointer and create it on first use or make it static too if IdentityKey is static.
static SignedPreKeyPair testReceiverSignedPreKeys(testReceiverIdentityKeys.getPrivateKey());

void RecievedFilesPage::on_decryptButton_clicked()
{
    if (selectedFileIndex < 0 || selectedFileIndex >= receivedFiles.size() || receivedFiles[selectedFileIndex].isDecrypted) {
        qDebug() << "Decrypt button clicked, but no valid file selected or file already decrypted.";
        return;
    }

    ReceivedFileInfo& selectedFile = receivedFiles[selectedFileIndex];
    qDebug() << "Attempting to decrypt file:" << selectedFile.fileName;
    
    // Use the statically generated receiver keys
    QByteArray receiverIdentityPrivEd_raw = toQByteArray(testReceiverIdentityKeys.getPrivateKey());
    QByteArray receiverSignedPrekeyPriv_raw = toQByteArray(testReceiverSignedPreKeys.getPrivateKey());

    qDebug() << "Test Receiver Identity Private Key (first 5 bytes):" << receiverIdentityPrivEd_raw.left(5).toHex();
    qDebug() << "Test Receiver Signed PreKey Private Key (first 5 bytes):" << receiverSignedPrekeyPriv_raw.left(5).toHex();

    if (selectedFile.senderEphemeralPublicKey.isEmpty() || selectedFile.senderIdentityPublicKeyEd.isEmpty()) {
        QMessageBox::critical(this, "Decryption Error", "Sender public keys are missing for the selected file.");
        qDebug() << "Decryption Error: Sender public keys missing for file:" << selectedFile.fileName;
        return;
    }

    DecryptionManager decryptionManager;
    QByteArray derivedKey = decryptionManager.deriveFileDecryptionKey(
        selectedFile, 
        receiverIdentityPrivEd_raw, 
        receiverSignedPrekeyPriv_raw
    );

    if (derivedKey.isEmpty()) {
        QMessageBox::critical(this, "Decryption Failed", "Could not derive decryption key for " + selectedFile.fileName);
        qDebug() << "Decryption failed for file:" << selectedFile.fileName;
        // The actual X3DH error would have been printed by DecryptionManager or X3DH_receiver.cpp
        return;
    }

    qDebug() << "Successfully derived decryption key for:" << selectedFile.fileName;
    qDebug() << "Derived Key (first 5 bytes):" << derivedKey.left(5).toHex();
    selectedFile.derivedDecryptionKey = derivedKey;
    selectedFile.isDecrypted = true; 

    if (selectedFile.displayBox) {
        selectedFile.statusLabel->setText("Status: Decrypted");
        selectedFile.statusLabel->setStyleSheet("color: #28a745;");
        selectedFile.displayBox->setStyleSheet("QFrame { background-color: #d4edda; border: 2px solid #007bff; border-radius: 4px; }");
    }
    
    updateButtonStates();
    QMessageBox::information(this, "Decryption Processed", selectedFile.fileName + " has been processed for decryption. Key derived.");
}

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