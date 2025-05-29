#include "KEKManager.h"
#include <sodium.h>
#include "stdexcept"
#include "KeyEncryptor.h"
#include "../crypto/crypto_utils.h"



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

void KEKManager::generateAndStoreUserKeys(const std::vector<unsigned char>& kek) {
    X3DHKeyBundle bundle;

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

    storeEncryptedKey("identityKey", encryptedIdentityKey.ciphertext, encryptedIdentityKey.nonce);
    storeEncryptedKey("signedPreKey", encryptedSignedPreKey.ciphertext, encryptedSignedPreKey.nonce);
    storeEncryptedKey("oneTimeKey", encryptedOneTimeKey.ciphertext, encryptedOneTimeKey.nonce);
}

void KEKManager::decryptAndStoredUserKeys(const std::vector<unsigned char>& kek) {
    KeyEncryptor::EncryptedData identityEncrypted = loadEncryptedKey("identityKey");
    KeyEncryptor::EncryptedData signedPreEncrypted = loadEncryptedKey("signedPreKey");
    KeyEncryptor::EncryptedData oneTimeEncrypted = loadEncryptedKey("oneTimeKey");

    auto decryptedIdentityKey = KeyEncryptor::decrypt(identityEncrypted, kek);
    auto decryptedSignedPreKey = KeyEncryptor::decrypt(signedPreEncrypted, kek);
    auto decryptedOneTimeKey = KeyEncryptor::decrypt(oneTimeEncrypted, kek);

    print_hex("Decrypted Identity Key: ", decryptedIdentityKey.data(), decryptedIdentityKey.size());
    print_hex("Decrypted Signed PreKey: ", decryptedSignedPreKey.data(), decryptedSignedPreKey.size());
    print_hex("Decrypted One Time Key: ", decryptedOneTimeKey.data(), decryptedOneTimeKey.size());
}



