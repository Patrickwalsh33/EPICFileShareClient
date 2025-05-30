#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include "../UploadPage/uploadpage.h"
#include "../../auth/UserAuthentication.h"


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

    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    qDebug() << username;
    qDebug() << password;

    UserAuthentication auth(nullptr);
    QString errorMsg;
    bool loginState = auth.loginUser(username, password, errorMsg);
    
    UploadPage registerDialog(nullptr); 


    if (loginState){
        qDebug()<< "Login Successful";
        UploadPage registerDialog(nullptr);
        
        registerDialog.setAttribute(Qt::WA_DeleteOnClose);
        this->accept(); 
        registerDialog.exec(); 

    }else{
        qDebug() << "login failed" << errorMsg;
    }





}









// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked";
}
