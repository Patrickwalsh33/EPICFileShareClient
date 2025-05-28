#pragma once

#include "../../key_management/DataEncryptionKey.h"
#include "uploadManager.h"
#include <QDialog>
#include <QString>
#include <QByteArray>
#include <vector>
#include <QFrame>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>

namespace Ui {
    class UploadPage;
}

class HoverButton : public QPushButton {
    Q_OBJECT
public:
    explicit HoverButton(QWidget *parent = nullptr) : QPushButton(parent) {
        setMouseTracking(true);
    }

protected:
    void enterEvent(QEnterEvent *event) override {
        if (isEnabled()) {
            setCursor(Qt::PointingHandCursor);
        }
        QPushButton::enterEvent(event);
    }

    void leaveEvent(QEvent *event) override {
        setCursor(Qt::ArrowCursor);
        QPushButton::leaveEvent(event);
    }
};

class ClickableFrame : public QFrame {
    Q_OBJECT
public:
    explicit ClickableFrame(QWidget *parent = nullptr) : QFrame(parent) {
        setMouseTracking(true);
        setFocusPolicy(Qt::StrongFocus);
    }

signals:
    void clicked();

protected:
    void mousePressEvent(QMouseEvent *event) override {
        if (event->button() == Qt::LeftButton) {
            emit clicked();
            event->accept();
        }
    }

    void enterEvent(QEnterEvent *event) override {
        setCursor(Qt::PointingHandCursor);
        QFrame::enterEvent(event);
    }

    void leaveEvent(QEvent *event) override {
        setCursor(Qt::ArrowCursor);
        QFrame::leaveEvent(event);
    }
};

struct FileInfo {
    QString path;
    QByteArray originalData;
    QByteArray encryptedData;
    QByteArray encryptedFileNonce;
    QByteArray encryptedDek;
    QByteArray encryptedDekNonce;
    std::vector<unsigned char> dek;
    bool isEncrypted;
    ClickableFrame* displayBox;
    QLabel* nameLabel;
    QLabel* sizeLabel;
    QLabel* typeLabel;
    QLabel* statusLabel;
    size_t index;
};

//declaring upload class that inherits from QDialog
class UploadPage : public QDialog
{
    //macro that enables use of signals and slots
    //preprocessor directive that runs before compiling
Q_OBJECT

public:
    explicit UploadPage(QWidget *parent = nullptr);
    ~UploadPage();

private slots:
    void on_selectFileButton_clicked();
    void on_encryptButton_clicked();   // 🔐 NEW: Handles encryption
    void on_uploadButton_clicked();
    void on_backButton_clicked();
    void onFileBoxClicked(size_t index);

private:
    Ui::UploadPage *ui;
    std::vector<FileInfo> files;
    size_t selectedFileIndex;
    uploadManager *uploader;

    void updateFileInfo(size_t index);
    void createFileBox(FileInfo& fileInfo);
    void updateButtonStates();
    QString formatFileSize(qint64 size);
};
