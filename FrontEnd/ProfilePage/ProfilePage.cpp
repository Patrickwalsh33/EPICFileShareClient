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

// Helper method to securely clear sensitive data
void ProfilePage::clearSensitiveData(QByteArray& data) {
    if (!data.isEmpty()) {
        data.fill(0);  // Overwrite with zeros
        data.clear();  // Clear the array
    }
}

// slot that handles change password button
void ProfilePage::on_changePasswordButton_clicked()
{
    // Step 1: Get old password
    QString oldPassword = ui->oldPasswordLineEdit->text();
    qDebug() << "Step 1: Got old password from input field";

    if (oldPassword.isEmpty()) {
        ui->messageLabel->setText("Please enter your current password");
        ui->messageLabel->setStyleSheet("color: red;");
        return;
    }

    // Step 2: Get and validate new password
    QString newPassword = ui->newPasswordLineEdit->text();
    QString confirmNewPassword = ui->confirmPasswordLineEdit->text();
    qDebug() << "Step 2: Validating new password";

    if (newPassword.isEmpty() || confirmNewPassword.isEmpty()) {
        qDebug() << "Step 2: New password validation failed - empty fields";
        ui->messageLabel->setText("Please enter and confirm your new password");
        ui->messageLabel->setStyleSheet("color: red;");
        return;
    }

    if (newPassword == oldPassword) {
        qDebug() << "Step 2: New password validation failed - same as old password";
        ui->messageLabel->setText("New password must be different from current password");
        ui->messageLabel->setStyleSheet("color: red;");
        return;
    }

    QString errorMsg;
    if (!passwordValidator->validatePassword(newPassword, confirmNewPassword, errorMsg)) {
        qDebug() << "Step 2: New password validation failed -" << errorMsg;
        ui->messageLabel->setText(errorMsg);
        ui->messageLabel->setStyleSheet("color: red;");
        return;
    }

    // Step 3: Verify old password by attempting to decrypt KEK
    try {
        QByteArray oldMasterKey = userAuth->deriveKeyFromPassword(oldPassword);
        QByteArray decryptedKEK = userAuth->decryptKEK(oldMasterKey);
        
        if (decryptedKEK.isEmpty()) {
            qDebug() << "Step 3: Failed to decrypt KEK - incorrect password";
            ui->messageLabel->setText("Current password is incorrect");
            ui->messageLabel->setStyleSheet("color: red;");
            return;
        }
        qDebug() << "Step 3: Successfully decrypted KEK with old password";

        // Step 4: Derive new master key and update KEK encryption
        QByteArray newMasterKey = userAuth->deriveNewKeyFromPassword(newPassword);
        if (!userAuth->updateKEKEncryption(decryptedKEK, newMasterKey)) {
            qDebug() << "Step 4: Failed to update KEK encryption";
            ui->messageLabel->setText("Failed to update password encryption");
            ui->messageLabel->setStyleSheet("color: red;");
            return;
        }
        qDebug() << "Step 4: Successfully updated KEK encryption";

    } catch (const std::exception& e) {
        qDebug() << "Error during password change:" << e.what();
        ui->messageLabel->setText("Error updating password encryption");
        ui->messageLabel->setStyleSheet("color: red;");
        return;
    }

    // Clear all password fields
    ui->oldPasswordLineEdit->clear();
    ui->newPasswordLineEdit->clear();
    ui->confirmPasswordLineEdit->clear();

    // Show success message
    ui->messageLabel->setText("Password changed successfully!");
    ui->messageLabel->setStyleSheet("color: green;");
    qDebug() << "Password change completed successfully";
}

void ProfilePage::on_backButton_clicked()
{
    reject();
    qDebug() << "Back button clicked on ProfilePage";
} 