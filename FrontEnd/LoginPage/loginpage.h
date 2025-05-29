#pragma once
#include <QDialog>
#include "loginManager.h"

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
    void on_goToRegistationButton_clicked(); // Slot for handling goToRegistationButton clicks.
    void onChallengeReceived(const QByteArray &nonce);
    void onChallengeFailed(const QString &error);
    void onLoginSucceeded();
    void onLoginFailed(const QString &error);


private:
    Ui::LoginPage *ui; // Pointer to the auto-generated UI class from loginpage.ui.
    LoginManager *loginManager;
    QByteArray currentNonce; // Store the received nonce for signing
    QString currentUsername;
};
