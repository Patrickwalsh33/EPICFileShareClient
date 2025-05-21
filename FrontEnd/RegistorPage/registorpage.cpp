#include "registorpage.h"
#include "ui_registorpage.h"
#include <QDebug>
#include "../LoginPage/loginpage.h"

// Constructor: Initializes the RegistorPage dialog and sets up the UI
RegistorPage::RegistorPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RegistorPage)
{
    ui->setupUi(this);
}

// Destructor: Deletes the UI object to free resources
RegistorPage::~RegistorPage()
{
    delete ui;
}

// Slot for handling the registerButton's clicked signal
void RegistorPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked";
    // TODO: Implement registration functionality
    // - Validate that both password fields match
    // - Save new user credentials to database
}

// Slot for handling the backToLoginButton's clicked signal
void RegistorPage::on_backToLoginButton_clicked()
{
    qDebug() << "backToLoginButton_clicked";
    
    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);
    
    this->accept(); // Close RegistorPage
    
    loginDialog.exec(); // Show LoginPage modally
} 