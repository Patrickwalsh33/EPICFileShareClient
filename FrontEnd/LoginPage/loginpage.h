#ifndef LOGINPAGE_H
#define LOGINPAGE_H

#include <QDialog>
#include "../../auth/UserAuthentication.h"
namespace Ui {
class LoginPage;
}

// Defines the LoginPage dialog window.
class LoginPage : public QDialog
{
    Q_OBJECT // Enables Qt's meta-object system (signals, slots, etc.).

public:
    explicit LoginPage(QWidget *parent = nullptr); // Constructor: Initializes the LoginPage.
    ~LoginPage(); // Destructor: Cleans up resources.

private slots:
    void on_loginButton_clicked(); // Slot for handling loginButton clicks.
    void on_backToLandingButton_clicked(); // Slot for handling backToLandingButton clicks.

private:
    Ui::LoginPage *ui; // Pointer to the auto-generated UI class from loginpage.ui.

    UserAuthentication userauthentication;
    QByteArray currentNonce; // Store the received nonce for signing
    QString currentUsername;
    std::string user;
    std::string package;

};

#endif 