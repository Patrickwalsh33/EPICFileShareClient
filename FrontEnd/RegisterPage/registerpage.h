#ifndef REGISTERPAGE_H
#define REGISTERPAGE_H

#include <QDialog>
#include "../../auth/UserAuthentication.h"
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

namespace Ui {
class RegisterPage;
}

// Defines the RegisterPage dialog window.
class RegisterPage : public QDialog
{
    Q_OBJECT   //this is a Qt macro for enabling signals and slots etc

public:
    explicit RegisterPage(QWidget *parent = nullptr); // explicit prevents implicit type conversion i
    ~RegisterPage();

private slots:
    void on_registerButton_clicked();
    void on_backToLoginButton_clicked();
    void onServerRegistrationSucceeded();
    void onServerRegistrationFailed(const QString &error);

signals:
    void registrationSucceeded();
    void registrationFailed(const QString &error);

private:
    Ui::RegisterPage *ui; // Pointer to the auto-generated UI class
    
    // Auth components
    CommonPasswordChecker* passwordChecker;
    PasswordValidator* passwordValidator;
    UserAuthentication* userAuth;

    int failed;
    std::string package;
    std::string user;
};

#endif 