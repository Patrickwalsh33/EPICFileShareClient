#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>            //for debug output
#include <QMessageBox>        //for displaying messages
#include "../LoginPage/loginpage.h"   //include the login page for redirection
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

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
}

// Destructor
RegisterPage::~RegisterPage()
{
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
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
    if (!userAuth->registerUser(username, password, confirmPassword, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        return;
    }
    
    // Show success message
    QMessageBox::information(this, "Registration Successful", 
                          "Your account has been created successfully.\n"
                          "You will now be redirected to the login page.");
    
    // Navigate to login page
    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);
    
    this->accept(); // Close RegisterPage
    
    loginDialog.exec(); // Show LoginPage modally
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