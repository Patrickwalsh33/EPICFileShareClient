#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>
#include <QMessageBox>
#include "../LoginPage/loginpage.h"
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../LandingPage/landingpage.h"



static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";


RegisterPage::RegisterPage(QWidget *parent) :
    QDialog(parent),  //calls the parent constructor
    ui(new Ui::RegisterPage) //creates ui object
{
    ui->setupUi(this);
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false); // Hide error label initially

    passwordChecker = new CommonPasswordChecker();
    passwordValidator = new PasswordValidator(passwordChecker);
    userAuth = new UserAuthentication(passwordValidator, package1, user1, this);

    connect(userAuth, &UserAuthentication::registrationSucceeded,
            this, &RegisterPage::onServerRegistrationSucceeded);
    connect(userAuth, &UserAuthentication::registrationFailed,
            this, &RegisterPage::onServerRegistrationFailed);
}

RegisterPage::~RegisterPage()
{
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
}

void RegisterPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked";
    
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
    QString errorMessage;

    if (!userAuth->registerUser(username, password, confirmPassword, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        ui->errorLabel->setVisible(true);
        return;
    }
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false);
}

void RegisterPage::onServerRegistrationSucceeded()
{
    qDebug() << "Server registration succeeded";

    ui->registerButton->setEnabled(true);
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false);

    LoginPage *loginDialog = new LoginPage(nullptr);
    loginDialog->setAttribute(Qt::WA_DeleteOnClose);

    this->accept();

    loginDialog->exec();
}

void RegisterPage::onServerRegistrationFailed(const QString &error)
{
    qDebug() << "Server registration failed:" << error;

    // Re-enable button
    ui->registerButton->setEnabled(true);

    // Show error message
    ui->errorLabel->setText("Server registration failed: " + error);
    ui->errorLabel->setStyleSheet("color: red");
    ui->errorLabel->setVisible(true);
}


void RegisterPage::on_backToLoginButton_clicked()
{
    qDebug() << "backToLoginButton_clicked";
    LandingPage landingDialog(nullptr);
    landingDialog.setAttribute(Qt::WA_DeleteOnClose);
    this->accept(); // Close RegisterPage
    landingDialog.exec(); // Show LandingPage
}
