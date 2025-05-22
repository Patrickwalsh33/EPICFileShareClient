#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>            //for debug output
#include <QMessageBox>        //for displaying messages
#include "../LoginPage/loginpage.h"   //include the login page for redirection

// Constructor
RegisterPage::RegisterPage(QWidget *parent) :
    QDialog(parent),  //calls the parent constructor
    ui(new Ui::RegisterPage) //creates ui object
{
    ui->setupUi(this);
    ui->errorLabel->setText(""); // this clears the error message initially
    
    // Load common passwords
    commonPasswords = loadCommonPasswordsFromCSV();
    qDebug() << "Loaded" << commonPasswords.size() << "common passwords"; //should be about 10000
}

// Destructor
RegisterPage::~RegisterPage()
{
    delete ui;
}

//:: pretty much lets the compiler now tha loadCommonPasswordsFromCsv() is  function in RegisterPage class
QStringList RegisterPage::loadCommonPasswordsFromCSV(){ 
    QStringList paswords;       //list to store passwords
    QFile file("common_passwords.csv");         //opens csv file
    
    if (file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QTextStream in(&file);     //create stream to read the file

        //skip the header line
        if (!in.atEnd()){
            in.readLine();
        }
        
        // Read passwords from the first column
        while (!in.atEnd()) {
            QString line = in.readLine();
            QStringList fields = line.split(',');
            if (!fields.isEmpty()) {
                paswords << fields[0].trimmed();
            }
        }

        file.close();    
    } else {
        qDebug() << "failed to open the common passwords file";
    }

    return paswords;
}

bool RegisterPage::validatePassword(const QString& password, const QString& confirmPassword, QString& errorMsg){
    
    //First check if the passwords match
    if (password!= confirmPassword){
        errorMsg= "Passwords dont match";
        return false;
    } 

    // Check the minimum length
    if (password.length() < 8){
        errorMsg = "Password must be at least 8 characters long";
        return false;
    }

    if (commonPasswords.contains(password.toLower())){
        errorMsg = "This password is too commonly used ";
        return false;
    }

    bool hasRepeats = false;
    for (int i = 0; i < password.length() - 2; i++){
        if (password[i] == password[i + 1] && password[i] == password[i+2]){
            hasRepeats = true;
            break;
        }
    }

    if (hasRepeats){
        errorMsg = "password contains too many repeated characters";
        return false;
    }
    
    return true;
}

// Validates username
bool RegisterPage::validateUsername(const QString& username, QString& errorMsg)
{
    if (username.isEmpty()) {
        errorMsg = "Username cannot be empty";
        return false;
    }
    
    if (username.length() < 6) {
        errorMsg = "Username must be at least 6 characters long";
        return false;
    }
    
    // Check for spaces
    if (username.contains(' ')) {
        errorMsg = "Username cannot contain spaces";
        return false;
    }
    
    return true;
}

// Slot for handling the registerButton's clicked signal
void RegisterPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked"; //remove this later
    
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
    QString errorMessage;
    
    // Validate username
    if (!validateUsername(username, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        return;
    }
    
    // Validate password
    if (!validatePassword(password, confirmPassword, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        return;
    }
    
    // If we get here, validation passed
    
    // TODO: Save new user credentials to database
    
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