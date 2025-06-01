#include "sentfilespage.h"
#include "ui_sentfilespage.h"
#include "../HomePage/homepage.h"
#include <QDebug>

SentFilesPage::SentFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SentFilesPage)
{
    ui->setupUi(this);
    // add get method to display files sent to server
}

SentFilesPage::~SentFilesPage()
{
    delete ui;
}

void SentFilesPage::on_backButton_clicked()
{
    this->accept();
    HomePage *homePage = new HomePage("", nullptr);
    homePage->setAttribute(Qt::WA_DeleteOnClose);
    homePage->exec();
}

void SentFilesPage::on_revokeButton_clicked()
{
    // add functionality to revoke access
} 