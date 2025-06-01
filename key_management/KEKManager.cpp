#include "KEKManager.h"

#include <iostream>
#include <QString>
#include <sodium.h>
#include "stdexcept"
#include "KeyEncryptor.h"
#include "../crypto/crypto_utils.h"
static const std::string package1 = "leftovers.project";
static const std::string user1 = "tempUser";

KEKManager::KEKManager(const std::string& package, const std::string& user)
    : keyEncryptor_(package, user)
{

}


void KEKManager::encryptKEK(

    const std::vector<unsigned char>& masterKey,
    const std::vector<unsigned char>& kek,
    std::vector<unsigned char>& nonceOut){

    if (masterKey.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid master key size");
    }
    keychain::Error keychainError;
    nonceOut.resize(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonceOut.data(), nonceOut.size());

    std::vector<unsigned char> ciphertext(kek.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long ciphertext_len;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        ciphertext.data(), &ciphertext_len,
        kek.data(), kek.size(),
        nullptr, 0,
        nullptr,
        nonceOut.data(),
        masterKey.data()
        );
    ciphertext.resize(ciphertext_len);

    keyEncryptor_.storeEncryptedKey("Enkek", ciphertext, nonceOut, keychainError);
    if (keychainError)
    {
        throw std::runtime_error("Error encrypting");
    }std::cout<<"Encrypted Kek stored successfully to OS keychain";
}

std::vector<unsigned char> KEKManager::decryptKEK(
        const std::vector<unsigned char>& masterKey,
        const std::vector<unsigned char>& encryptedKEK,
        const std::vector<unsigned char>& nonce) {

    if (masterKey.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid master key size");
    }

    std::vector<unsigned char> decryptedKEK(encryptedKEK.size() - crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decryptedKEK_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decryptedKEK.data(), &decryptedKEK_len,
            nullptr,
            encryptedKEK.data(), encryptedKEK.size(),
            nullptr, 0,
            nonce.data(),
            masterKey.data()) != 0)
    {
        throw std::runtime_error("Invalid encryption key");
    }

    decryptedKEK.resize(decryptedKEK_len);
    return decryptedKEK;
}


void KEKManager::generateAndStoreUserKeys(const std::vector<unsigned char>& kek) {
    X3DHKeyBundle bundle;

    keychain::Error keychainError;

    auto identityPrivateKey = bundle.identityKeyPair.getPrivateKey();
    auto signedPreKeyPrivate = bundle.signedPreKeyPair.getPrivateKey();
    auto oneTimeKeyPrivate = bundle.oneTimeKeyPair.getPrivateKey();

    auto encryptedIdentityKey = KeyEncryptor::encrypt(identityPrivateKey, kek);
    print_hex("Encrypted Identity Key Ciphertext: ", encryptedIdentityKey.ciphertext.data(), encryptedIdentityKey.ciphertext.size());
    print_hex("Encrypted Identity Key Nonce: ", encryptedIdentityKey.nonce.data(), encryptedIdentityKey.nonce.size());

    auto encryptedSignedPreKey = KeyEncryptor::encrypt(signedPreKeyPrivate, kek);
    print_hex("Encrypted Signed PreKey Ciphertext: ", encryptedSignedPreKey.ciphertext.data(), encryptedSignedPreKey.ciphertext.size());
    print_hex("Encrypted Signed PreKey Nonce: ", encryptedSignedPreKey.nonce.data(), encryptedSignedPreKey.nonce.size());

    auto encryptedOneTimeKey = KeyEncryptor::encrypt(oneTimeKeyPrivate, kek);
    print_hex("Encrypted One Time Key Ciphertext: ", encryptedOneTimeKey.ciphertext.data(), encryptedOneTimeKey.ciphertext.size());
    print_hex("Encrypted One Time Key Nonce: ", encryptedOneTimeKey.nonce.data(), encryptedOneTimeKey.nonce.size());

    keyEncryptor_.storeEncryptedKey("identityKey", encryptedIdentityKey.ciphertext, encryptedIdentityKey.nonce,keychainError);
    keyEncryptor_.storeEncryptedKey("signedPreKey", encryptedSignedPreKey.ciphertext, encryptedSignedPreKey.nonce,keychainError);
    keyEncryptor_.storeEncryptedKey("oneTimeKey", encryptedOneTimeKey.ciphertext, encryptedOneTimeKey.nonce,keychainError);
}

void KEKManager::decryptStoredUserKeys(const std::vector<unsigned char>& kek) {
    keychain::Error keychainError;

    KeyEncryptor::EncryptedData identityEncrypted = keyEncryptor_.loadEncryptedKey("identityKey",keychainError);
    KeyEncryptor::EncryptedData signedPreEncrypted = keyEncryptor_.loadEncryptedKey("signedPreKey",keychainError);
    KeyEncryptor::EncryptedData oneTimeEncrypted = keyEncryptor_.loadEncryptedKey("oneTimeKey",keychainError);

    auto decryptedIdentityKey = KeyEncryptor::decrypt(identityEncrypted, kek);
    auto decryptedSignedPreKey = KeyEncryptor::decrypt(signedPreEncrypted, kek);
    auto decryptedOneTimeKey = KeyEncryptor::decrypt(oneTimeEncrypted, kek);

    print_hex("Decrypted Identity Key: ", decryptedIdentityKey.data(), decryptedIdentityKey.size());
    print_hex("Decrypted Signed PreKey: ", decryptedSignedPreKey.data(), decryptedSignedPreKey.size());
    print_hex("Decrypted One Time Key: ", decryptedOneTimeKey.data(), decryptedOneTimeKey.size());
}





