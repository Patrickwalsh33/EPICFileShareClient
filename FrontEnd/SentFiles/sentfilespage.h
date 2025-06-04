#ifndef SENTFILESPAGE_H
#define SENTFILESPAGE_H

#include <QDialog>
#include <QVector>
#include <QString>
#include <QByteArray>
#include <QLabel>
#include <QFrame>
#include "sentfilesmanager.h"

namespace Ui {
class SentFilesPage;
}


struct SentFileInfo {
    QString uuid;
    int index;


    QFrame* displayBox = nullptr;
    QLabel* nameLabel = nullptr;
    QLabel* statusLabel = nullptr;
};

class SentFilesPage : public QDialog
{
    Q_OBJECT

public:
    explicit SentFilesPage(QWidget *parent = nullptr);
    ~SentFilesPage();

protected:
    bool eventFilter(QObject *watched, QEvent *event) override;

private slots:
    void on_backButton_clicked();
    void on_revokeButton_clicked();
    void on_deleteButton_clicked();
    void on_getSentFilesButton_clicked();
    void onFileBoxClicked(int index);

    // Slots for handling responses from SentFilesManager
    void handleOwnedFileUuidsResponse(const QByteArray &serverResponse);
    void handleFetchUuidsError(const QString &error);
    void handleFileDeleteSuccess(const QString &deleted_uuid, const QByteArray &serverResponse);
    void handleFileDeleteError(const QString &failed_uuid, const QString &error);

private:
    Ui::SentFilesPage *ui;
    SentFilesManager *m_sentFilesManager;
    QVector<SentFileInfo> sentFilesList;
    int selectedFileIndex = -1;

    void createFileBox(SentFileInfo& fileInfo);
    void updateButtonStates();
};

#endif // SENTFILESPAGE_H 