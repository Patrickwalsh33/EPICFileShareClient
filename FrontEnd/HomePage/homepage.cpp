#include "homepage.h"
#include "ui_homepage.h" 
#include "../ProfilePage/ProfilePage.h"
#include "../UploadPage/uploadpage.h"
#include <QDebug>

HomePage::HomePage(const QString &username, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::HomePage),
    currentUsername(username)
{
    ui->setupUi(this);
    ui->welcomeLabel->setText(QString("Welcome, %1!").arg(currentUsername));
}

HomePage::~HomePage()
{
    delete ui;
}

void HomePage::on_profileButton_clicked()
{
    qDebug() << "Profile button clicked on HomePage for user:" << currentUsername;
    ProfilePage *profilePage = new ProfilePage(currentUsername, this);
    profilePage->setAttribute(Qt::WA_DeleteOnClose);
    profilePage->exec();
}

void HomePage::on_uploadButton_clicked()
{
    qDebug() << "Upload button clicked on HomePage for user:" << currentUsername;
    UploadPage *uploadPage = new UploadPage(this);
    uploadPage->setAttribute(Qt::WA_DeleteOnClose);
    uploadPage->exec();
}

