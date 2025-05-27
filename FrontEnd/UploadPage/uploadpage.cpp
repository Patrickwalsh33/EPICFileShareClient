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
        uploader(new uploadManager(this)),
        selectedFileIndex(static_cast<size_t>(-1)) {  // Initialize with invalid index
    ui->setupUi(this);

    ui->uploadButton->setEnabled(false);
    ui->encryptButton->setEnabled(false);
    ui->uploadButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");
    ui->encryptButton->setStyleSheet("color: #666666; background-color: #e0e0e0; border: none; border-radius: 5px; font-size: 14px;");

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
        QFile file(fileName);
        if (!file.open(QIODevice::ReadOnly)) {
            QMessageBox::warning(this, "File Error", "Failed to open selected file.");
            return;
        }

        FileInfo newFile;
        newFile.path = fileName;
        newFile.originalData = file.readAll();
        newFile.isEncrypted = false;
        newFile.dek = DataEncryptionKey().getKey();
        newFile.index = files.size();  // Set the index before adding to vector
        file.close();

        files.push_back(newFile);  // Add to vector first
        createFileBox(files.back());  // Then create the box
        updateFileInfo(files.size() - 1);  // Update info for the new file
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

void UploadPage::on_encryptButton_clicked() {
    if (selectedFileIndex >= files.size() || files[selectedFileIndex].isEncrypted) {
        return;
    }

    auto& selectedFile = files[selectedFileIndex];
    unsigned long long ciphertext_len;
    std::vector<unsigned char> ciphertext(selectedFile.originalData.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    std::vector<unsigned char> nonce(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    encrypt_with_chacha20(
            reinterpret_cast<const unsigned char*>(selectedFile.originalData.constData()),
            selectedFile.originalData.size(),
            selectedFile.dek.data(),
            ciphertext.data(),
            &ciphertext_len,
            nonce.data()
    );

    selectedFile.encryptedData = QByteArray(reinterpret_cast<const char*>(ciphertext.data()), ciphertext_len);
    selectedFile.encryptionNonce = QByteArray(reinterpret_cast<const char*>(nonce.data()), nonce.size());
    selectedFile.encryptedDek = QByteArray(reinterpret_cast<const char*>(selectedFile.dek.data()), selectedFile.dek.size());
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
        return;
    }

    const auto& selectedFile = files[selectedFileIndex];
    uploader->uploadFile(selectedFile.encryptedData, selectedFile.encryptedDek);
}

void UploadPage::on_backButton_clicked() {
    reject();
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
