#include "KeyEncryptor.h"
#include <sodium.h>
#include <stdexcept>

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

