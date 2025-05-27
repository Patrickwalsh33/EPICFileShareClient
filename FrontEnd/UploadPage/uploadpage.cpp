#include "uploadpage.h"
#include "ui_uploadpage.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QFile>
#include <QDebug>
#include "../../crypto/crypto_utils.h"

UploadPage::UploadPage(QWidget *parent) :
        QDialog(parent),
        ui(new Ui::UploadPage),
        uploader(new uploadManager(this)) {
    ui->setupUi(this);

    ui->uploadButton->setEnabled(false);
    ui->encryptButton->setEnabled(false); // Disable encryption initially
    ui->selectedFileLabel->setText("No file selected");
    ui->fileSizeLabel->setText("");
    ui->fileTypeLabel->setText("");

    uploader->setServerUrl("https://leftovers.gobbler.info:3333");

    connect(uploader, &uploadManager::uploadSucceeded, this, [=]() {
        QMessageBox::information(this, "Upload Success", "File uploaded successfully.");
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

    if (!fileName.isEmpty()) {
        selectedFilePath = fileName;

        QFile file(selectedFilePath);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "File Error", "Failed to open selected file.");
            return;
        }

        originalFileData = file.readAll();  // Load file into memory
        file.close();

        dek = DataEncryptionKey().getKey(); // Generate new DEK on selection
        updateFileInfo();
        ui->encryptButton->setEnabled(true);
        ui->uploadButton->setEnabled(false); // Must encrypt before upload
        qDebug() << "File selected and loaded into memory:" << selectedFilePath;
    }
}

void UploadPage::on_encryptButton_clicked() {
    if (originalFileData.isEmpty()) {
        QMessageBox::warning(this, "Encryption Error", "No file loaded to encrypt.");
        return;
    }

    unsigned long long ciphertext_len;
    std::vector<unsigned char> ciphertext(originalFileData.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    std::vector<unsigned char> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    encrypt_with_chacha20(
            reinterpret_cast<const unsigned char*>(originalFileData.constData()),
            originalFileData.size(),
            dek.data(),
            ciphertext.data(),
            &ciphertext_len,
            nonce.data()
    );

    encryptedFileData = QByteArray(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
    encryptionNonce = QByteArray(reinterpret_cast<const char*>(nonce.data()), nonce.size());

    // Encrypt DEK for storage/transmission (here we just copy it, you'd normally encrypt it with KEK)
    EncryptedDek = QByteArray(reinterpret_cast<const char*>(dek.data()), dek.size());

    ui->uploadButton->setEnabled(true);
    ui->encryptButton->setEnabled(false); // Prevent double encryption
    
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
    if (encryptedFileData.isEmpty() || EncryptedDek.isEmpty()) {
        QMessageBox::warning(this, "Upload Error", "Encrypted data is missing.");
        return;
    }

    uploader->uploadFile(encryptedFileData, EncryptedDek);
}

void UploadPage::on_backButton_clicked() {
    reject(); // Close the dialog
    qDebug() << "Back button clicked";
}

void UploadPage::updateFileInfo() {
    if (selectedFilePath.isEmpty()) {
        ui->selectedFileLabel->setText("No file selected");
        ui->fileSizeLabel->setText("");
        ui->fileTypeLabel->setText("");
        return;
    }

    QFileInfo fileInfo(selectedFilePath);
    ui->selectedFileLabel->setText("Selected: " + fileInfo.fileName());

    qint64 size = fileInfo.size();
    QString sizeText;
    if (size < 1024)
        sizeText = QString("%1 bytes").arg(size);
    else if (size < 1024 * 1024)
        sizeText = QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    else if (size < 1024 * 1024 * 1024)
        sizeText = QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    else
        sizeText = QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);

    ui->fileSizeLabel->setText("Size: " + sizeText);
    QString fileType = fileInfo.suffix().isEmpty() ? "Unknown" : fileInfo.suffix().toUpper() + " File";
    ui->fileTypeLabel->setText("Type: " + fileType);
}
