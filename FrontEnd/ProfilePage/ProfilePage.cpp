#include "ProfilePage.h"
#include "ui_ProfilePage.h"
#include <QDebug>

ProfilePage::ProfilePage(const QString &username, QWidget *parent) :
    QDialog(parent),       //initalise parent class first
    ui(new Ui::ProfilePage),     //create ui object
    currentUsername(username)      //store the username passed in
{
    ui->setupUi(this);      //setup ui 
    ui->messageLabel->setText("");       //clear any initial message
    
    // Initialize password checking components
    passwordChecker = new CommonPasswordChecker();       //creates password checker
    passwordValidator = new PasswordValidator(passwordChecker);      //create validator
    userAuth = new UserAuthentication(passwordValidator, package, user, this);    //create authentication
}

//destructor
ProfilePage::~ProfilePage(){
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
}

//updates message label with green and red colors
void ProfilePage::updateMessageLabel(const QString& message, bool isError)
{
    ui->messageLabel->setText(message);
    if (isError) {
        ui->messageLabel->setStyleSheet("color: red;");
    } else {
        ui->messageLabel->setStyleSheet("color: green;");
    }
}

// slot that handles change password button
void ProfilePage::on_changePasswordButton_clicked()
{
     //get username and password from ui. -> is used to a passwordLineEdit. calls text() to retrieve content
    QString oldPassword = ui->oldPasswordLineEdit->text();
    QString newPassword = ui->newPasswordLineEdit->text();
    QString confirmNewPassword = ui->confirmPasswordLineEdit->text();

    // Clear previous message
    ui->messageLabel->clear();

    // Basic validation
    if (oldPassword.isEmpty() || newPassword.isEmpty() || confirmNewPassword.isEmpty()) {
        updateMessageLabel("Please fill in all password fields", true);
        return;
    }

    // Verify old password by attempting to login
    QString errorMsg;
    if (!userAuth->loginUser(currentUsername, oldPassword, errorMsg)) {
        updateMessageLabel("Current password is incorrect", true);
        return;
    }

    // Validate new password
    if (!passwordValidator->validatePassword(newPassword, confirmNewPassword, errorMsg)) {
        updateMessageLabel(errorMsg, true);
        return;
    }

    // Register new password
    if (userAuth->registerUser(currentUsername, newPassword, confirmNewPassword, errorMsg)) {
        updateMessageLabel("Password changed successfully!", false);
        
        // Clear the input fields
        ui->oldPasswordLineEdit->clear();
        ui->newPasswordLineEdit->clear();
        ui->confirmPasswordLineEdit->clear();
    } else {
        updateMessageLabel("Failed to change password: " + errorMsg, true);
    }
}

void ProfilePage::on_backButton_clicked()
{
    reject();
    qDebug() << "Back button clicked on ProfilePage";
} 