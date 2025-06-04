#ifndef LOGINPAGE_H
#define LOGINPAGE_H
#include <QDialog>
#include "../../auth/UserAuthentication.h" 

namespace Ui { // prevent naming collisons and are good for organsing code
class LoginPage; 
}

// Defines the LoginPage dialog window. inherits from QDialog
class LoginPage : public QDialog
{
    Q_OBJECT //qt macro for signals and slots

public:
    // Constructor 
    explicit LoginPage(QWidget *parent = nullptr); 
// Destructor
    ~LoginPage(); 

private slots:
    void on_loginButton_clicked(); 
    void on_backToLandingButton_clicked(); 
    void handleLoginSucceeded(const QString &username);

private:
    Ui::LoginPage *ui; 
    UserAuthentication* userauthentication;
    QByteArray currentNonce; // Store the received nonce for signing
    QString currentUsername;
    std::string user;
    std::string package; 

};

#endif 