#include "crypto_utils.h"
#include <iostream>
#include <cstdio>
#include <cstring>

void print_hex(const char* label, const unsigned char* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    std::cout << std::endl;
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
