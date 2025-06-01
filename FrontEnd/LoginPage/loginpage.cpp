#include "loginpage.h"
#include "ui_loginpage.h" // Make sure this is present if using a .ui file
#include <QDebug>
#include "../HomePage/homepage.h"
#include "../../auth/UserAuthentication.h"
#include "../../auth/CommonPasswordChecker.h"
#include "../../auth/validation.h" // Make sure this is included for PasswordValidator

static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";

// Constructor: Initializes the LoginPage dialog and sets up the UI from login.ui.
LoginPage::LoginPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::LoginPage),
    userauthentication(new PasswordValidator(new CommonPasswordChecker()), package1, user1 , this)
{
    ui->setupUi(this);

    // CRITICAL: Connect UserAuthentication signals to LoginPage slots
    // These connections are essential for the asynchronous flow to work!
    connect(&userauthentication, &UserAuthentication::loginSucceeded,
            this, &LoginPage::onLoginSucceeded);
    connect(&userauthentication, &UserAuthentication::loginFailed,
            this, &LoginPage::onLoginFailed);
    connect(&userauthentication, &UserAuthentication::challengeReceived,
            this, &LoginPage::onChallengeReceived);
    connect(&userauthentication, &UserAuthentication::challengeFailed,
            this, &LoginPage::onChallengeFailed);

    // Connect your UI buttons as well, if not done in .ui file directly
    connect(ui->loginButton, &QPushButton::clicked,
            this, &LoginPage::on_loginButton_clicked);
    connect(ui->goToRegistationButton, &QPushButton::clicked,
            this, &LoginPage::on_goToRegistationButton_clicked);
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

    QString errorMsg;
    // Use the member variable 'userauthentication' to initiate the login process
    bool loginProcessInitiated = userauthentication.loginUser(username, password, errorMsg);

    // The loginUser() call initiates an asynchronous process (like sending a network request).
    // The result (success/failure) will come back via signals (loginSucceeded/loginFailed/challengeReceived/challengeFailed).
    // So, you should NOT transition to HomePage directly here.
    if (loginProcessInitiated){
        qDebug() << "Login process initiated for user:" << username;
        // Optionally, display a "Logging in..." message to the user here.
        // ui->statusLabel->setText("Logging in..."); // If you have a status label
    } else {
        qDebug() << "Login initiation failed for user:" << username << "Error:" << errorMsg;
        // Directly call the slot that handles login failure to update your UI
        onLoginFailed(errorMsg);
    }
}

// Slot for handling the goToRegistationButton's clicked signal.
void LoginPage::on_goToRegistationButton_clicked()
{
    qDebug() << "goToRegistationButton_clicked from LoginPage";
    // Add logic here to navigate to your registration page
    // Example:
    // RegisterPage *registerPage = new RegisterPage(this);
    // registerPage->exec(); // Or show(), depending on your flow
}

// --- MISSING SLOT IMPLEMENTATIONS (ADD THESE!) ---



void LoginPage::onLoginSucceeded() {
    qDebug() << "LoginPage: Login succeeded! (Bypassing HomePage navigation for now).";
    this->accept(); // Close the LoginPage dialog

    // Commented out to bypass 'getCurrentUsername' error for testing login functionality
    // HomePage *homePage = new HomePage(userauthentication.getCurrentUsername(), nullptr);
    // homePage->setAttribute(Qt::WA_DeleteOnClose);
    // homePage->exec();
}

void LoginPage::onLoginFailed(const QString &errorMsg) {
    qWarning() << "LoginPage: Final login failed:" << errorMsg;
    // Update your UI to show the error message to the user
    // Example:
    // ui->statusLabel->setText("Login failed: " + errorMsg);
}

void LoginPage::onChallengeFailed(const QString &errorMsg) {
    qWarning() << "LoginPage: Challenge process failed:" << errorMsg;
    // You might want to show a specific error for challenge failure, or just route to general login failed
    onLoginFailed(errorMsg); // Routes to the general login failed message
}

void LoginPage::onChallengeReceived(const QByteArray &nonce) {
    qDebug() << "LoginPage: Challenge received! Nonce (Base64):" << nonce.toBase64();
    // This slot is called when UserAuthentication emits challengeReceived.
    // At this point, UserAuthentication should internally handle the nonce signing
    // and then call submitLogin() itself. LoginPage usually doesn't need to do
    // anything directly with the nonce here, other than perhaps log it or update a status.
    // If your design requires LoginPage to hold the nonce and trigger submitLogin:
    // currentNonce = nonce;
    // userauthentication.submitLogin(currentUsername, /* signature here */, nonce);
    // (This would require currentUsername to be set when on_loginButton_clicked is called)
}