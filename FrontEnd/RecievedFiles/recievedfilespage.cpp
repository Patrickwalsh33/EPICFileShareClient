#include "recievedfilespage.h"
#include "ui_recievedfilespage.h"
#include "../HomePage/homepage.h"
#include <QDebug>

RecievedFilesPage::RecievedFilesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::RecievedFilesPage)
{
    ui->setupUi(this);
    // put get method here to display all the files received
}

RecievedFilesPage::~RecievedFilesPage()
{
    delete ui;
}

void RecievedFilesPage::on_backButton_clicked()
{
    this->accept();
    HomePage *homePage = new HomePage("", nullptr);
    homePage->setAttribute(Qt::WA_DeleteOnClose);
    homePage->exec();
}

void RecievedFilesPage::on_decryptButton_clicked()
{
    // decrypt logic here
}

void RecievedFilesPage::on_downloadButton_clicked()
{
    // download functionality here
} 