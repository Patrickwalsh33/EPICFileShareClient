//
// Created by Andrew Jaffray on 23/05/2025.
//

// You may need to build the project (run Qt uic code generator) to get "ui_uploadpage.h" resolved

#include "uploadpage.h"
#include "ui_uploadpage.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QFileInfo>
#include <QDebug>


// Constructor: Initializes the UploadPage dialog and sets up the UI.
UploadPage::UploadPage(QWidget *parent) :
        QDialog(parent),
        ui(new Ui::UploadPage),
        uploader(new uploadManager(this)) {
    ui->setupUi(this);

    // Initially disable the upload button until a file is selected
    ui->uploadButton->setEnabled(false);
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
// Destructor: Deletes the UI object to free resources.
UploadPage::~UploadPage()
{
    delete ui;
}

// Slot for handling the selectFileButton's clicked signal
void UploadPage::on_selectFileButton_clicked()
{
    // Open file dialog to select any type of file
    QString fileName = QFileDialog::getOpenFileName(
            this,
            "Select File to Upload",
            QDir::homePath(), // Start in the user's home directory
            "All Files (*.*)" // Allow all file types
    );

    if (!fileName.isEmpty()) {
        selectedFilePath = fileName;
        updateFileInfo();
        ui->uploadButton->setEnabled(true);
        qDebug() << "File selected:" << selectedFilePath;
    }
}

// Slot for handling the uploadButton's clicked signal
void UploadPage::on_uploadButton_clicked() {
    qDebug() << "Upload button clicked for file:" << selectedFilePath;
    if (selectedFilePath.isEmpty()) {
        QMessageBox::warning(this, "Upload Error", "Please select a file first.");
        return;
    }

    QFileInfo fileInfo(selectedFilePath);
    QString message = QString(
                              "Selected file: %1\n"
                              "File size: %2 bytes\n"
                              "File type: %3")
            .arg(fileInfo.fileName())
            .arg(fileInfo.size())
            .arg(fileInfo.suffix().isEmpty() ? "Unknown" : fileInfo.suffix().toUpper());

    qDebug() << "Attempting to upload file:" << selectedFilePath;
    QByteArray fileData = "ADD THE ENCRYPTED FILE DATA HERE";
    QByteArray dek = "ADD THE DEK HERE";
    uploader->uploadFile(fileData, dek);
}

// Slot for handling the backButton's clicked signal
void UploadPage::on_backButton_clicked()
{
    // Close the upload page and return to the previous page
    reject(); // Close the dialog
    qDebug() << "Back button clicked";
}

// Updates the file information display
void UploadPage::updateFileInfo()
{
    if (selectedFilePath.isEmpty()) {
        ui->selectedFileLabel->setText("No file selected");
        ui->fileSizeLabel->setText("");
        ui->fileTypeLabel->setText("");
        return;
    }

    QFileInfo fileInfo(selectedFilePath);

    // Update the labels with file information
    ui->selectedFileLabel->setText("Selected: " + fileInfo.fileName());

    // Format file size in a human-readable way
    qint64 size = fileInfo.size();
    QString sizeText;
    if (size < 1024) {
        sizeText = QString("%1 bytes").arg(size);
    } else if (size < 1024 * 1024) {
        sizeText = QString("%1 KB").arg(size / 1024.0, 0, 'f', 1);
    } else if (size < 1024 * 1024 * 1024) {
        sizeText = QString("%1 MB").arg(size / (1024.0 * 1024.0), 0, 'f', 1);
    } else {
        sizeText = QString("%1 GB").arg(size / (1024.0 * 1024.0 * 1024.0), 0, 'f', 1);
    }
    ui->fileSizeLabel->setText("Size: " + sizeText);

    // Display file type
    QString fileType = fileInfo.suffix().isEmpty() ? "Unknown" : fileInfo.suffix().toUpper() + " File";
    ui->fileTypeLabel->setText("Type: " + fileType);
}
