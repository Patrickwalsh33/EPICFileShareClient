#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include "../HomePage/homepage.h"
#include "../../auth/UserAuthentication.h"
#include "../UploadPage/uploadpage.h"
#include "../LandingPage/landingpage.h"


static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser"; //default user

// Constructor: Initializes the LoginPage dialog and sets up the UI from login.ui.
LoginPage::LoginPage(QWidget *parent) :
    QDialog(parent), //initalise parent
    ui(new Ui::LoginPage) {

    ui->setupUi(this);
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false); // Hide error label initially

    //create authenticaion handler with password validation
    userauthentication = new UserAuthentication(new PasswordValidator(new CommonPasswordChecker()), package1, user1, this);
    connect(userauthentication, &UserAuthentication::loginSucceeded,
            this, &LoginPage::handleLoginSucceeded);
}

// Destructor: 
LoginPage::~LoginPage() {
    delete ui;
}

// Slot for handling the loginButton's clicked signal.
void LoginPage::on_loginButton_clicked(){

    //get username and password from ui. -> is used to a passwordLineEdit. calls text() to retrieve content
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();

    // Create UserAuthentication with proper parameters
    PasswordValidator* validator = new PasswordValidator(new CommonPasswordChecker());
    UserAuthentication auth(validator, package1, user1, this);
    QString errorMsg;
    if (!userauthentication->loginUser(username, password, errorMsg)) {
        qDebug() << "Initial login flow setup failed synchronously:" << errorMsg;
        ui->loginButton->setEnabled(true);
        ui->errorLabel->setText(errorMsg);
        ui->errorLabel->setVisible(true);
        return;
    }

    // Clean up
    delete validator;

    //update UI state afrer login attempt
    ui->loginButton->setEnabled(false);
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false);

}

//handles login called when authentication emits loginSucceded
void LoginPage::handleLoginSucceeded(const QString &username)
{
    //reset ui elements
    ui->loginButton->setEnabled(true);
    ui->errorLabel->clear();
    ui->errorLabel->setVisible(false);

    //close login with success status
    this->accept(); 

    //create and show homepage
    HomePage *homePage = new HomePage(username, nullptr); // Create a new HomePage instance
    homePage->setAttribute(Qt::WA_DeleteOnClose); // Ensures the HomePage object is deleted
    homePage->exec();
}




// Slot for handling the backToLandingButton's clicked signal.
void LoginPage::on_backToLandingButton_clicked() {
    LandingPage landingDialog(nullptr);
    landingDialog.setAttribute(Qt::WA_DeleteOnClose);
    this->accept(); // Close LoginPage
    landingDialog.exec(); // Show LandingPage modally
}
