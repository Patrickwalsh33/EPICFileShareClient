#ifndef RECIEVEDFILESPAGE_H
#define RECIEVEDFILESPAGE_H

#include <QDialog>

namespace Ui {
class RecievedFilesPage;
}

class RecievedFilesPage : public QDialog
{
    Q_OBJECT

public:
    explicit RecievedFilesPage(QWidget *parent = nullptr);
    ~RecievedFilesPage();

private slots:
    void on_backButton_clicked();
    void on_decryptButton_clicked(); // decrypt logic here
    void on_downloadButton_clicked(); // download functionality here

private:
    Ui::RecievedFilesPage *ui;
};

#endif // RECIEVEDFILESPAGE_H 