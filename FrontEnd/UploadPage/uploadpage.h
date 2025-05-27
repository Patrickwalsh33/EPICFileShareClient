#pragma once

#include "../../key_management/DataEncryptionKey.h"
#include "uploadManager.h"
#include <QDialog>
#include <QString>
#include <QByteArray>
#include <vector>

namespace Ui {
    class UploadPage;
}

class UploadPage : public QDialog
{
Q_OBJECT

public:
    explicit UploadPage(QWidget *parent = nullptr);
    ~UploadPage();

private slots:
    void on_selectFileButton_clicked();
    void on_encryptButton_clicked();   // 🔐 NEW: Handles encryption
    void on_uploadButton_clicked();
    void on_backButton_clicked();

private:
    Ui::UploadPage *ui;
    QString selectedFilePath;
    QByteArray originalFileData;
    QByteArray encryptedFileData;
    QByteArray encryptionNonce;
    QByteArray EncryptedDek;
    std::vector<unsigned char> dek;

    uploadManager *uploader;

    void updateFileInfo();
    bool encryptSelectedFile();
};
