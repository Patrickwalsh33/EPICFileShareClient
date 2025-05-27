#include "changepasswordpage.h"
#include "ui_changepasswordpage.h"
#include <QDebug>            //for debug output
#include <QMessageBox>        //for displaying messages
#include <QTimer>            //for auto-clearing success messages
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"

// Constructor
ChangePasswordPage::ChangePasswordPage(QWidget *parent) :
    QDialog(parent),  //calls the parent constructor
    ui(new Ui::ChangePasswordPage) //creates ui object
{
    ui->setupUi(this);
    ui->errorLabel->setText(""); // this clears the error message initially
    ui->successLabel->setText(""); // this clears the success message initially
    
    // Initialize auth components
    passwordChecker = new CommonPasswordChecker();
    passwordValidator = new PasswordValidator(passwordChecker);
    userAuth = new UserAuthentication(passwordValidator);
}

// Destructor
ChangePasswordPage::~ChangePasswordPage()
{
    clearSensitiveData(); // Clear any sensitive data before destruction
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
}

// Slot for handling the changePasswordButton's clicked signal
void ChangePasswordPage::on_changePasswordButton_clicked()
{
    qDebug() << "changePasswordButton_clicked";
    
    // TODO: Implement change password functionality
    // Steps to implement:
    // 1. Get input values from UI fields
    // 2. Validate current password against stored credentials
    // 3. Validate new password using PasswordValidator
    // 4. Check new password is different from current
    // 5. Update user credentials securely
    // 6. Clear sensitive data from memory
    // 7. Show success/error messages
    
    ui->errorLabel->setText("Change password functionality not yet implemented");
    ui->errorLabel->setStyleSheet("color: orange");
    ui->successLabel->setText("");
    
    qDebug() << "Change password functionality not yet implemented";
}

// Slot for handling the cancelButton's clicked signal
void ChangePasswordPage::on_cancelButton_clicked()
{
    qDebug() << "cancelButton_clicked";
    
    // Clear sensitive data before closing
    clearSensitiveData();
    
    this->reject(); // Close ChangePasswordPage without saving
}

// Helper method to clear sensitive data from memory
void ChangePasswordPage::clearSensitiveData()
{
    // Clear all password fields
    ui->currentPasswordLineEdit->clear();
    ui->newPasswordLineEdit->clear();
    ui->confirmNewPasswordLineEdit->clear();
    
    // Overwrite the text with zeros for security
    ui->currentPasswordLineEdit->setText(QString(50, '\0'));
    ui->newPasswordLineEdit->setText(QString(50, '\0'));
    ui->confirmNewPasswordLineEdit->setText(QString(50, '\0'));
    
    // Clear again
    ui->currentPasswordLineEdit->clear();
    ui->newPasswordLineEdit->clear();
    ui->confirmNewPasswordLineEdit->clear();
}

// Helper method to show success message
void ChangePasswordPage::showSuccessMessage()
{
    ui->successLabel->setText("Password changed successfully!");
    ui->successLabel->setStyleSheet("color: green; font-weight: bold;");
    ui->errorLabel->setText(""); // Clear any error messages
    
    qDebug() << "Password change successful";
} 