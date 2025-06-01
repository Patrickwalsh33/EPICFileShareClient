#include "KeyEncryptor.h"
#include <sodium.h>
#include <stdexcept>
#include "keychain/keychain.h"
#include "../crypto/crypto_utils.h"
#include <iostream>

KeyEncryptor::KeyEncryptor(const std::string& package, const std::string& user)
    :package_(package), user_(user)
{

}

KeyEncryptor::EncryptedData KeyEncryptor::encrypt(
        const std::vector<unsigned char>& plaintext,
        const std::vector<unsigned char>& kek) {

    if (kek.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid KEK size");
    }

    EncryptedData result;
    result.nonce.resize(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(result.nonce.data(), result.nonce.size());

    result.ciphertext.resize(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            result.ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            nullptr, 0, // additional data (not used)
            nullptr,
            result.nonce.data(),
            kek.data()) != 0) {
        throw std::runtime_error("Encryption failed");
    }

    result.ciphertext.resize(ciphertext_len);
    return result;
}

std::vector<unsigned char> KeyEncryptor::decrypt(
        const EncryptedData& encryptedData,
        const std::vector<unsigned char>& kek) {

    if (kek.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid KEK size");
    }

    std::vector<unsigned char> decrypted(encryptedData.ciphertext.size() -
                                         crypto_aead_chacha20poly1305_ietf_ABYTES);
    unsigned long long decrypted_len;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted.data(), &decrypted_len,
            nullptr,
            encryptedData.ciphertext.data(), encryptedData.ciphertext.size(),
            nullptr, 0,
            encryptedData.nonce.data(),
            kek.data()) != 0) {
        throw std::runtime_error("Decryption failed");
    }

    decrypted.resize(decrypted_len);
    return decrypted;
}
void KeyEncryptor::storeEncryptedKey(
        const std::string& keyName,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& nonce,

        keychain::Error& keychainError
) {
    // Encode to base64
    std::string ciphertextB64 = base64Encode(ciphertext);
    std::string nonceB64 = base64Encode(nonce);

    // Store ciphertext and nonce as separate entries
    keychain::setPassword(package_, keyName + "_ciphertext", user_, ciphertextB64, keychainError);
    if (keychainError) {
        std::cerr << "Error storing ciphertext for " << keyName << ": " << keychainError.message << std::endl;
        return;
    }

    keychain::setPassword(package_, keyName + "_nonce", user_, nonceB64, keychainError);
    if (keychainError) {
        std::cerr << "Error storing nonce for " << keyName << ": " << keychainError.message << std::endl;
        return;
    }
}
KeyEncryptor::EncryptedData KeyEncryptor::loadEncryptedKey(
        const std::string& keyName,
        keychain::Error& keychainError
    ) {

    std::string ciphertextB64 = keychain::getPassword(package_, keyName + "_ciphertext", user_, keychainError);

    if (keychainError) {
        throw std::runtime_error("Failed to load ciphertext for " + keyName + ": " + keychainError.message);
    }

    std::string nonceB64 = keychain::getPassword(package_, keyName + "_nonce", user_, keychainError);
    if (keychainError) {
        throw std::runtime_error("Failed to load nonce for " + keyName + ": " + keychainError.message);
    }

    KeyEncryptor::EncryptedData encryptedData;
    encryptedData.ciphertext = base64Decode(ciphertextB64);
    encryptedData.nonce = base64Decode(nonceB64);

    return encryptedData;
}


