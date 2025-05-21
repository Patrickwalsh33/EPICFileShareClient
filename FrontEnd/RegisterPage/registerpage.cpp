#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>
#include "../LoginPage/loginpage.h"

// Constructor: Initializes the RegisterPage dialog and sets up the UI
RegisterPage::RegisterPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RegisterPage)
{
    ui->setupUi(this);
}

// Destructor: Deletes the UI object to free resources
RegisterPage::~RegisterPage()
{
    delete ui;
}

// Slot for handling the registerButton's clicked signal
void RegisterPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked";
    // TODO: Implement registration functionality
    // - Validate that both password fields match
    // - Save new user credentials to database
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