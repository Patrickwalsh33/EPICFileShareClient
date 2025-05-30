#include "homepage.h"
#include "ui_homepage.h" // Will be generated from homepage.ui
#include "../ProfilePage/ProfilePage.h"
// #include "../UploadPage/uploadpage.h" // Removed
// #include "../LoginPage/loginpage.h"   // Removed
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

