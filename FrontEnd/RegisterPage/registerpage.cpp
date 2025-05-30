#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>
#include <QMessageBox>
#include "../LoginPage/loginpage.h"
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"




// Constructor
RegisterPage::RegisterPage(QWidget *parent) :
    QDialog(parent),  //calls the parent constructor
    ui(new Ui::RegisterPage) //creates ui object
{
    ui->setupUi(this);
    ui->errorLabel->setText(""); // this clears the error message initially
    
    // Initialize auth components
    passwordChecker = new CommonPasswordChecker();
    passwordValidator = new PasswordValidator(passwordChecker);
    userAuth = new UserAuthentication(passwordValidator);

    registerManager = new RegisterManager(this);
    registerManager ->setServerUrl("https://leftovers.gobbler.info");

    connect(registerManager, &RegisterManager::registrationSucceeded,
            this, &RegisterPage::onServerRegistrationSucceeded);
    connect(registerManager, &RegisterManager::registrationFailed,
            this, &RegisterPage::onServerRegistrationFailed);
}

// Destructor
RegisterPage::~RegisterPage()
{
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
    delete registerManager;
}

// Slot for handling the registerButton's clicked signal
void RegisterPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked"; //remove this later
    
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
    QString errorMessage;

    // Register user using the authentication service
    if (!userAuth->registerUserLocally(username, password, confirmPassword, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        return;
    }

    ui->errorLabel->setText("Registering with server...");
    ui->errorLabel->setStyleSheet("color: blue");
    ui->registerButton->setEnabled(false);

    if (!registerManager->registerUserWithManager(username)) {
        ui->errorLabel->setText("Failed to start server registration");
        ui->errorLabel->setStyleSheet("color: red");
        ui->registerButton->setEnabled(true);
    }
}

void RegisterPage::onServerRegistrationSucceeded()
{
    qDebug() << "Server registration succeeded";

    ui->registerButton->setEnabled(true);

    QMessageBox::information(this, "Registration Successful",
                             "Your account has been created successfully.\n"
                             "You will now be redirected to the login page.");

    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);

    this->accept();

    loginDialog.exec();


}

void RegisterPage::onServerRegistrationFailed(const QString &error)
{
    qDebug() << "Server registration failed:" << error;

    // Re-enable button
    ui->registerButton->setEnabled(true);

    // Show error message
    ui->errorLabel->setText("Server registration failed: " + error);
    ui->errorLabel->setStyleSheet("color: red");
}


// Slot for handling the backToLoginButton's clicked signal
void RegisterPage::on_backToLoginButton_clicked()
{
    qDebug() << "backToLoginButton_clicked";
    
    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);
    
    this->accept(); // Close RegisterPage
    
    loginDialog.exec(); // Show LoginPage modally
}