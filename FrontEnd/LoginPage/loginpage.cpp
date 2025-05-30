#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include "../HomePage/homepage.h"
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

    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    qDebug() << "Attempting login for user:" << username;

    UserAuthentication auth(nullptr);
    QString errorMsg;
    bool loginState = auth.loginUser(username, password, errorMsg);
    

    if (loginState){

        qDebug()<< "Login Successful";
        UploadPage registerDialog(nullptr);

        //TODO: This is only authenticating locally
        registerDialog.setAttribute(Qt::WA_DeleteOnClose);
        this->accept(); 
        registerDialog.exec(); 

  /*
        qDebug()<< "Login Successful for user:" << username;

        this->accept();
        HomePage *homePage = new HomePage(username, nullptr);
        homePage->setAttribute(Qt::WA_DeleteOnClose);
        homePage->exec();
        */


    }else{
        qDebug() << "Login failed for user:" << username << "Error:" << errorMsg;
    }

}









// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked from LoginPage";
}
