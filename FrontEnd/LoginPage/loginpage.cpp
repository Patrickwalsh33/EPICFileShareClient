#include "loginpage.h"
#include "ui_loginpage.h"
#include <QDebug>
#include "../HomePage/homepage.h"
#include "../../auth/UserAuthentication.h"
#include "../UploadPage/uploadpage.h"
#include "../LandingPage/landingpage.h"


static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";

// Constructor: Initializes the LoginPage dialog and sets up the UI from login.ui.
LoginPage::LoginPage(QWidget *parent) :
    QDialog(parent),

    ui(new Ui::LoginPage),
    userauthentication(new PasswordValidator(new CommonPasswordChecker()), package1, user1 , this)

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

    // Create UserAuthentication with proper parameters
    PasswordValidator* validator = new PasswordValidator(new CommonPasswordChecker());
    UserAuthentication auth(validator, package1, user1, this);
    QString errorMsg;
    bool loginState = auth.loginUser(username, password, errorMsg);
    
    // Clean up
    delete validator;

    if (loginState){
        qDebug()<< "Login Successful for user:" << username;
        this->accept();
        HomePage *homePage = new HomePage(username, nullptr);
        homePage->setAttribute(Qt::WA_DeleteOnClose);
        homePage->exec();
    }else{
        qDebug() << "Login failed for user:" << username << "Error:" << errorMsg;
    }

}









// Slot for handling the goToRegistationButton's clicked signal.


// Slot for handling the backToLandingButton's clicked signal.
void LoginPage::on_backToLandingButton_clicked()
{
    qDebug() << "backToLandingButton_clicked from LoginPage";
    LandingPage landingDialog(nullptr);
    landingDialog.setAttribute(Qt::WA_DeleteOnClose);
    this->accept(); // Close LoginPage
    landingDialog.exec(); // Show LandingPage modally
}
