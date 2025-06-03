#include "homepage.h"
#include "ui_homepage.h" 
#include "../ProfilePage/ProfilePage.h"
#include "../UploadPage/uploadpage.h"
#include "../SentFiles/sentfilespage.h"
#include "../RecievedFiles/recievedfilespage.h"
#include <QDebug> //Qt debugng utility

//Constructor Implementaion
//uses initaliztion list. lets you set inital values of class data member
HomePage::HomePage(const QString &username, QWidget *parent) :
    QDialog(parent),    //initalizes parent class
    ui(new Ui::HomePage),   //creates ui instance
    currentUsername(username)   //initalizes username member
{
    ui->setupUi(this);
    ui->welcomeLabel->setText("Welcome to the Leftovers Home Page");
}

//destructor
HomePage::~HomePage() {
    delete ui;
}

//event handler for profile button
void HomePage::on_profileButton_clicked() {
    ProfilePage *profilePage = new ProfilePage(currentUsername, this); //creates new profilePage dialog
    profilePage->setAttribute(Qt::WA_DeleteOnClose); //auto deletes on close
    profilePage->exec();  
}

//event handler for upload button
void HomePage::on_uploadButton_clicked() {
    UploadPage *uploadPage = new UploadPage(this); 
    uploadPage->setAttribute(Qt::WA_DeleteOnClose);
    uploadPage->exec();
}

//event handler for sent files button
void HomePage::on_filesSentButton_clicked() {
    SentFilesPage *sentFilesPage = new SentFilesPage(this);
    sentFilesPage->setAttribute(Qt::WA_DeleteOnClose);
    sentFilesPage->exec();
}

//event handler for received files button
void HomePage::on_filesReceivedButton_clicked() {
    RecievedFilesPage *recievedFilesPage = new RecievedFilesPage(this);
    recievedFilesPage->setAttribute(Qt::WA_DeleteOnClose);
    recievedFilesPage->exec();
}

