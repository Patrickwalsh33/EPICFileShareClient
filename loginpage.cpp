#include "loginpage.h"
#include "ui_login.h"
#include <QDebug>

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
void LoginPage::on_loginButton_clicked()
{
    qDebug() << "loginButton_clicked";
}

// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked";
} 