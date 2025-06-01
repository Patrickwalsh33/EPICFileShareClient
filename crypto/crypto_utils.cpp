#include "crypto_utils.h"
#include <iostream>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cctype>
#include "keychain/keychain.h"


void print_hex(const char* label, const unsigned char* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    std::cout << std::endl;
}

X3DHKeyBundle::X3DHKeyBundle()
        : identityKeyPair(),
          signedPreKeyPair(identityKeyPair.getPrivateKey()),
          oneTimeKeyPair() {
    print_hex("Identity Private Key: ", identityKeyPair.getPrivateKey().data(), identityKeyPair.getPrivateKey().size());
    print_hex("Identity Public Key: ", identityKeyPair.getPublicKey().data(), identityKeyPair.getPublicKey().size());
    print_hex("Signed PreKey Private: ", signedPreKeyPair.getPrivateKey().data(), signedPreKeyPair.getPrivateKey().size());
    print_hex("Signed Prekey Public: ", signedPreKeyPair.getPublicKey().data(), signedPreKeyPair.getPublicKey().size());
    print_hex("One Time Key Private: ", oneTimeKeyPair.getPrivateKey().data(), oneTimeKeyPair.getPrivateKey().size());
    print_hex("One Time Key Public: ", oneTimeKeyPair.getPublicKey().data(), oneTimeKeyPair.getPublicKey().size());
}

bool derive_key_from_shared_secret(
        const unsigned char* shared_secret,
        unsigned char* derived_key_out,
        const char context[8],
        uint64_t subkey_id) {
    if (crypto_kdf_derive_from_key(
            derived_key_out,
            crypto_aead_chacha20poly1305_ietf_KEYBYTES,
            subkey_id,
            context,
            shared_secret) != 0) {
        std::cerr << "[Error] Failed to derive symmetric key." << std::endl;
        return false;
    }
    return true;
}

void encrypt_with_chacha20(const unsigned char* plaintext, unsigned long long plaintext_len,
                           const unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
                           unsigned char* ciphertext, unsigned long long* ciphertext_len,
                           unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]) {
    randombytes_buf(nonce, crypto_aead_chacha20poly1305_ietf_NPUBBYTES);

    crypto_aead_chacha20poly1305_ietf_encrypt(
            ciphertext, ciphertext_len,
            plaintext, plaintext_len,
            NULL, 0,
            NULL,
            nonce,
            key);
}

bool decrypt_with_chacha20(const unsigned char* ciphertext, unsigned long long ciphertext_len,
                           const unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
                           const unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
                           unsigned char* decrypted, unsigned long long* decrypted_len) {
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decrypted, decrypted_len,
            NULL,
            ciphertext, ciphertext_len,
            NULL, 0,
            nonce,
            key) != 0) {
        std::cerr << "[Error] Decryption failed. Authentication tag mismatch." << std::endl;
        return false;
    }
    return true;
}

bool decrypt_dek(
        const std::vector<unsigned char>& encryptedDek,
        unsigned long long encryptedDekLen,
        const std::vector<unsigned char>& dekNonce,
        const unsigned char* derivedKey,
        std::vector<unsigned char>& decryptedDekOut
) {
    decryptedDekOut.resize(encryptedDekLen - crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long decryptedLen = 0;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            decryptedDekOut.data(), &decryptedLen,
            nullptr,
            encryptedDek.data(), encryptedDekLen,
            nullptr, 0,
            dekNonce.data(),
            derivedKey
    ) != 0) {
        std::cerr << "[X3DH] Failed to decrypt DEK." << std::endl;
        return false;
    }

    if (decryptedLen != decryptedDekOut.size()) {
        std::cerr << "[X3DH] Decrypted DEK size mismatch." << std::endl;
        return false;
    }

    std::cout << "[X3DH] DEK successfully decrypted and verified." << std::endl;
    return true;
}

static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

static inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64Encode(const std::vector<unsigned char>& data) {
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    int data_len = static_cast<int>(data.size());
    int pos = 0;

    while (data_len--) {
        char_array_3[i++] = data[pos++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for(i = 0; i <4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while((i++ < 3))
            ret += '=';
    }

    return ret;
}

std::vector<unsigned char> base64Decode(const std::string& encoded_string) {
    int in_len = static_cast<int>(encoded_string.size());
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::vector<unsigned char> ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = static_cast<unsigned char>(strchr(base64_chars, char_array_4[i]) - base64_chars);

            char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

            for (i = 0; i < 3; i++)
                ret.push_back(char_array_3[i]);
            i = 0;
        }
    }

    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;

        for (j = 0; j <4; j++)
            char_array_4[j] = static_cast<unsigned char>(strchr(base64_chars, char_array_4[j]) - base64_chars);

        char_array_3[0] = ( char_array_4[0] << 2       ) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) +   char_array_4[3];

        for (j = 0; j < i - 1; j++) ret.push_back(char_array_3[j]);
    }

    return ret;
}

// Define constants for package and user
static const std::string PACKAGE = "fileShare";
static const std::string USER = "username";  // swap for actual username
static keychain::Error keychainError;

//storing encrypted key + nonce


