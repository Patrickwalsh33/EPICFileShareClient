#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include "../UploadPage/uploadpage.h"
#include "../ChangePasswordPage/changepasswordpage.h"

// Constructor: Initializes the LoginPage dialog and sets up the UI from login.ui.
LoginPage::LoginPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LoginPage)
{
    ui->setupUi(this);
}

// Destructor: Deletes the UI object to free resources.
LoginPage::~LoginPage()
{
    delete ui;
}

// Slot for handling the loginButton's clicked signal.
void LoginPage::on_loginButton_clicked(){

    qDebug() << "loginButton_clicked";
    qDebug() << "navigating to UploadPage";

    UploadPage registerDialog(nullptr);
    registerDialog.setAttribute(Qt::WA_DeleteOnClose);

    this->accept(); // Close HomePage

    registerDialog.exec(); // Show Upload page modally
}

// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked";
}

// Slot for handling the changePasswordButton's clicked signal.
void LoginPage::on_changePasswordButton_clicked()
{
    qDebug() << "changePasswordButton_clicked on LoginPage";
    
    ChangePasswordPage changePasswordDialog(this);
    changePasswordDialog.setAttribute(Qt::WA_DeleteOnClose);
    
    // Show as modal dialog - don't close LoginPage
    changePasswordDialog.exec(); // Show ChangePasswordPage modally
}