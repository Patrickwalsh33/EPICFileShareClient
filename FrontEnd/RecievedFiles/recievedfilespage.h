#ifndef RECIEVEDFILESPAGE_H
#define RECIEVEDFILESPAGE_H

#include <QDialog>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QLabel>
#include <QFrame>

namespace Ui {
class RecievedFilesPage;
}

// Struct to hold information about each received file
struct ReceivedFileInfo {
    QString uuid;
    QString fileName;
    QString sender;
    qint64 fileSize;
    QByteArray encryptedData;
    QByteArray decryptedData;
    bool isDecrypted = false;
    bool isDownloaded = false; // Potentially useful later
    int index; // To identify the file in the QVector

    // UI elements associated with this file
    QFrame* displayBox = nullptr;
    QLabel* nameLabel = nullptr;
    QLabel* senderLabel = nullptr;
    QLabel* statusLabel = nullptr;
};

class RecievedFilesPage : public QDialog
{
    Q_OBJECT

public:
    explicit RecievedFilesPage(QWidget *parent = nullptr);
    ~RecievedFilesPage();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void on_backButton_clicked();
    void on_getFilesButton_clicked(); // Slot for the new button
    void on_decryptButton_clicked();
    void on_downloadButton_clicked();
    void onFileBoxClicked(int index); // Slot for when a file box is clicked

private:
    Ui::RecievedFilesPage *ui;
    QVector<ReceivedFileInfo> receivedFiles;
    int selectedFileIndex = -1; // Index of the currently selected file, -1 if none

    void createFileBox(ReceivedFileInfo& fileInfo);
    void updateButtonStates();
    void updateFileInfoDisplay(int index); // To update details of a selected file (optional)
    QString formatFileSize(qint64 size); // Helper for formatting file size
};

#endif // RECIEVEDFILESPAGE_H 