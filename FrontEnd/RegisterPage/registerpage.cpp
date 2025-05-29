#include "registerpage.h"
#include "ui_registerpage.h"
#include <QDebug>
#include <QMessageBox>
#include "../LoginPage/loginpage.h"
#include "../../auth/validation.h"
#include "../../auth/CommonPasswordChecker.h"
#include "../../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../../key_management/X3DHKeys/OneTimeKeyPair.h"
#include "../../key_management/KeyEncryptor.h"
#include "../../crypto/crypto_utils.h"
#include "keychain/keychain.h"



// Constructor
RegisterPage::RegisterPage(QWidget *parent) :
    QDialog(parent),  //calls the parent constructor
    ui(new Ui::RegisterPage) //creates ui object
{
    ui->setupUi(this);
    ui->errorLabel->setText(""); // this clears the error message initially
    
    // Initialize auth components
    passwordChecker = new CommonPasswordChecker();
    passwordValidator = new PasswordValidator(passwordChecker);
    userAuth = new UserAuthentication(passwordValidator);
}

// Destructor
RegisterPage::~RegisterPage()
{
    delete ui;
    delete passwordChecker;
    delete passwordValidator;
    delete userAuth;
}

// Slot for handling the registerButton's clicked signal
void RegisterPage::on_registerButton_clicked()
{
    qDebug() << "registerButton_clicked"; //remove this later
    
    QString username = ui->usernameLineEdit->text();
    QString password = ui->passwordLineEdit->text();
    QString confirmPassword = ui->confirmPasswordLineEdit->text();
    QString errorMessage;

    std::vector<unsigned char> kek = EncryptionKeyGenerator::generateKey(Encryption_KEY_SIZE);
    print_hex("KEK: ", kek.data(), kek.size());

    IdentityKeyPair receiverIdentity;
    SignedPreKeyPair receiverSignedPre(receiverIdentity.getPrivateKey());
    OneTimeKeyPair receiverOneTime;

    auto identityPrivateKey = receiverIdentity.getPrivateKey();
    print_hex("Identity Private Key: ", identityPrivateKey.data(), identityPrivateKey.size());

    auto signedPreKeyPrivate = receiverSignedPre.getPrivateKey();
    print_hex("Signed PreKey Private: ", signedPreKeyPrivate.data(), signedPreKeyPrivate.size());

    auto oneTimeKeyPrivate = receiverOneTime.getPrivateKey();
    print_hex("One Time Key Private: ", oneTimeKeyPrivate.data(), oneTimeKeyPrivate.size());

    auto encryptedIdentityKey = KeyEncryptor::encrypt(identityPrivateKey, kek);
    print_hex("Encrypted Identity Key Ciphertext: ", encryptedIdentityKey.ciphertext.data(), encryptedIdentityKey.ciphertext.size());
    print_hex("Encrypted Identity Key Nonce: ", encryptedIdentityKey.nonce.data(), encryptedIdentityKey.nonce.size());

    auto encryptedSignedPreKey = KeyEncryptor::encrypt(signedPreKeyPrivate, kek);
    print_hex("Encrypted Signed PreKey Ciphertext: ", encryptedSignedPreKey.ciphertext.data(), encryptedSignedPreKey.ciphertext.size());
    print_hex("Encrypted Signed PreKey Nonce: ", encryptedSignedPreKey.nonce.data(), encryptedSignedPreKey.nonce.size());

    auto encryptedOneTimeKey = KeyEncryptor::encrypt(oneTimeKeyPrivate, kek);
    print_hex("Encrypted One Time Key Ciphertext: ", encryptedOneTimeKey.ciphertext.data(), encryptedOneTimeKey.ciphertext.size());
    print_hex("Encrypted One Time Key Nonce: ", encryptedOneTimeKey.nonce.data(), encryptedOneTimeKey.nonce.size());



    // Register user using the authentication service
    if (!userAuth->registerUser(username, password, confirmPassword, errorMessage)) {
        ui->errorLabel->setText(errorMessage);
        ui->errorLabel->setStyleSheet("color: red");
        return;
    }
    
    // Show success message
    QMessageBox::information(this, "Registration Successful", 
                          "Your account has been created successfully.\n"
                          "You will now be redirected to the login page.");
    
    // Navigate to login page
    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);


    
    this->accept(); // Close RegisterPage
    
    loginDialog.exec(); // Show LoginPage modally
}

// Slot for handling the backToLoginButton's clicked signal
void RegisterPage::on_backToLoginButton_clicked()
{
    qDebug() << "backToLoginButton_clicked";
    
    LoginPage loginDialog(nullptr);
    loginDialog.setAttribute(Qt::WA_DeleteOnClose);
    
    this->accept(); // Close RegisterPage
    
    loginDialog.exec(); // Show LoginPage modally
} 