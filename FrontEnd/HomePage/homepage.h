#ifndef HOMEPAGE_H
#define HOMEPAGE_H

#include <QDialog>
#include <QString>

// Forward declarations
namespace Ui {
class HomePage;
}
class ProfilePage;
// class UploadPage;
// class LoginPage;

class HomePage : public QDialog
{
    Q_OBJECT

public:
    explicit HomePage(const QString &username, QWidget *parent = nullptr);
    ~HomePage();

private slots:
    void on_profileButton_clicked();
    // void on_uploadButton_clicked();
    // void on_logoutButton_clicked();

private:
    Ui::HomePage *ui;
    QString currentUsername;
};

#endif // HOMEPAGE_H 