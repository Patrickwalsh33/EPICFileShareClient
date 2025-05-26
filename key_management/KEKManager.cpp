#include "KEKManager.h"
#include "EncryptionKeyGenerator.h"
#include <sodium.h>
#include "stdexcept"



std::vector<unsigned char> KEKManager::encryptKEK(
    const std::vector<unsigned char>& masterKey,
    const std::vector<unsigned char>& kek,
    std::vector<unsigned char>& nonceOut){

    if (masterKey.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid master key size");
    }

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
    return ciphertext;

}

std::vector<unsigned char> KEKManager::decryptKEK(

    const std::vector<unsigned char>& masterKey,
    const std::vector<unsigned char>& encryptedKEK,
    std::vector<unsigned char>& nonce){

    if (masterKey.size() != crypto_aead_chacha20poly1305_ietf_KEYBYTES) {
        throw std::runtime_error("Invalid master key size");
    }

    nonce.resize(crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

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





