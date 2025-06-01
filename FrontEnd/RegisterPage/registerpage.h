#pragma once

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
    ~RegisterPage(); //destructor

private slots:
    void on_registerButton_clicked();
    void on_backToLoginButton_clicked();

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
