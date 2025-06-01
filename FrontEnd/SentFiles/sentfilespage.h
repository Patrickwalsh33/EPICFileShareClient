#ifndef SENTFILESPAGE_H
#define SENTFILESPAGE_H

#include <QDialog>

namespace Ui {
class SentFilesPage;
}

class SentFilesPage : public QDialog
{
    Q_OBJECT

public:
    explicit SentFilesPage(QWidget *parent = nullptr);
    ~SentFilesPage();

private slots:
    void on_backButton_clicked();
    void on_revokeButton_clicked(); // add functionality to revoke access

private:
    Ui::SentFilesPage *ui;
};

#endif // SENTFILESPAGE_H 