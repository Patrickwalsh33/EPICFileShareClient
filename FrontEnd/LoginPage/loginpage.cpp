#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include <QMessageBox>

#include "../UploadPage/uploadpage.h"
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../RegisterPage/registerpage.h"
#include <sodium.h>

// Constructor: Initializes the LoginPage dialog and sets up the UI from login.ui.
LoginPage::LoginPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LoginPage)
{
    ui->setupUi(this);

    loginManager = new LoginManager(this);
    loginManager->setServerUrl("https://leftovers.gobbler.info:3333");

    // Connect LoginManager signals
    connect(loginManager, &LoginManager::challengeReceived,
            this, &LoginPage::onChallengeReceived);
    connect(loginManager, &LoginManager::challengeFailed,
            this, &LoginPage::onChallengeFailed);
    connect(loginManager, &LoginManager::loginSucceeded,
            this, &LoginPage::onLoginSucceeded);
    connect(loginManager, &LoginManager::loginFailed,
            this, &LoginPage::onLoginFailed);
}

// Destructor: Deletes the UI object to free resources.
LoginPage::~LoginPage()
{
    delete ui;
    delete loginManager;
}

// Slot for handling the loginButton's clicked signal.
void LoginPage::on_loginButton_clicked(){


    QString username = ui->usernameLineEdit->text();

    if (username.isEmpty()) {
        QMessageBox::warning(this, "Login Error", "Username cannot be empty.");
        return;
    }

    currentUsername = username;

    qDebug() << "Requesting challenge for user:" << username;
    if (!loginManager->requestChallenge(username)) {
        QMessageBox::critical(this, "Login Error", "Failed to request challenge from server.");
    }
}

void LoginPage::onChallengeReceived(const QByteArray &nonce) {

    qDebug() << "Challenge received, nonce size:" << nonce.size();
    currentNonce = nonce;


}

void LoginPage::onChallengeFailed(const QString &error)
{
    qDebug() << "Challenge failed:" << error;
    QMessageBox::critical(this, "Challenge Failed", "Failed to get challenge from server: " + error);
}

void LoginPage::onLoginSucceeded()
{
    qDebug() << "Login successful!";

    QMessageBox::information(this, "Login Successful", "You have been successfully logged in!");

    // Navigate to upload page
    UploadPage uploadDialog(nullptr);
    uploadDialog.setAttribute(Qt::WA_DeleteOnClose);

    this->accept();
    uploadDialog.exec();
}

void LoginPage::onLoginFailed(const QString &error)
{
    qDebug() << "Login failed:" << error;
    QMessageBox::critical(this, "Login Failed", "Login failed: " + error);
}


// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked";
    RegisterPage registerDialog(nullptr);
    registerDialog.setAttribute(Qt::WA_DeleteOnClose);
    this->accept(); // Close LoginPage
    registerDialog.exec(); // Show RegisterPage modally

}