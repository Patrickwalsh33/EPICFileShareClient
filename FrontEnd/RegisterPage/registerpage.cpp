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
#include <iostream>



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

// Define constants for package and user
const std::string PACKAGE = "fileShare";
const std::string USER = "username";  // swap for actual username

keychain::Error error;

//storing encrypted key + nonce
void storeEncryptedKey(
        const std::string& keyName,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& nonce
) {
    // Encode to base64
    std::string ciphertextB64 = base64Encode(ciphertext);
    std::string nonceB64 = base64Encode(nonce);

    // Store ciphertext and nonce as separate entries
    keychain::setPassword(PACKAGE, keyName + "_ciphertext", USER, ciphertextB64, error);
    if (error) {
        std::cerr << "Error storing ciphertext for " << keyName << ": " << error.message << std::endl;
        return;
    }

    keychain::setPassword(PACKAGE, keyName + "_nonce", USER, nonceB64, error);
    if (error) {
        std::cerr << "Error storing nonce for " << keyName << ": " << error.message << std::endl;
        return;
    }
}

KeyEncryptor::EncryptedData loadEncryptedKey(const std::string& keyName) {
    keychain::Error error;

    std::string ciphertextB64 = keychain::getPassword(PACKAGE, keyName + "_ciphertext", USER, error);
    if (error) {
        throw std::runtime_error("Failed to load ciphertext for " + keyName + ": " + error.message);
    }

    std::string nonceB64 = keychain::getPassword(PACKAGE, keyName + "_nonce", USER, error);
    if (error) {
        throw std::runtime_error("Failed to load nonce for " + keyName + ": " + error.message);
    }

    KeyEncryptor::EncryptedData encryptedData;
    encryptedData.ciphertext = base64Decode(ciphertextB64);
    encryptedData.nonce = base64Decode(nonceB64);

    return encryptedData;
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

    //storing in os keychain
    storeEncryptedKey("identityKey", encryptedIdentityKey.ciphertext, encryptedIdentityKey.nonce);
    storeEncryptedKey("signedPreKey", encryptedSignedPreKey.ciphertext, encryptedSignedPreKey.nonce);
    storeEncryptedKey("oneTimeKey", encryptedOneTimeKey.ciphertext, encryptedOneTimeKey.nonce);

    KeyEncryptor::EncryptedData identityEncrypted = loadEncryptedKey("identityKey");
    KeyEncryptor::EncryptedData  signedPreEncrypted = loadEncryptedKey("signedPreKey");
    KeyEncryptor::EncryptedData  oneTimeEncrypted   = loadEncryptedKey("oneTimeKey");

    auto decryptedIdentityKey = KeyEncryptor::decrypt(identityEncrypted, kek);
    auto decryptedSignedPreKey = KeyEncryptor::decrypt(signedPreEncrypted, kek);
    auto decryptedOneTimeKey = KeyEncryptor::decrypt(oneTimeEncrypted, kek);

    print_hex("Decrypted Identity Key: ", decryptedIdentityKey.data(), decryptedIdentityKey.size());
    print_hex("Decrypted Signed PreKey: ", decryptedSignedPreKey.data(), decryptedSignedPreKey.size());
    print_hex("Decrypted One Time Key: ", decryptedOneTimeKey.data(), decryptedOneTimeKey.size());

    bool identityMatch = decryptedIdentityKey == identityPrivateKey;
    bool signedPreMatch = decryptedSignedPreKey == signedPreKeyPrivate;
    bool oneTimeMatch = decryptedOneTimeKey == oneTimeKeyPrivate;

    if (identityMatch && signedPreMatch && oneTimeMatch) {
        std::cout << "Success: All decrypted keys match the original keys!" << std::endl;
    } else {
        std::cerr << "Failure: One or more decrypted keys do not match the originals!" << std::endl;
    }


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
