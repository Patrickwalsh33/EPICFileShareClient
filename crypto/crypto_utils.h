#pragma once

#include <sodium.h>
#include <cstddef>
#include <vector>
#include <string>
#include "../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../key_management/X3DHKeys/OneTimeKeyPair.h"
#include "keychain/keychain.h"
#include "../../key_management/KeyEncryptor.h"

void print_hex(const char* label, const unsigned char* data, size_t len);


struct X3DHKeyBundle {
    IdentityKeyPair identityKeyPair;
    SignedPreKeyPair signedPreKeyPair;
    OneTimeKeyPair oneTimeKeyPair;

    X3DHKeyBundle();
};

// Derive a symmetric key from the shared secret using libsodium KDF
bool derive_key_from_shared_secret(
        const unsigned char* shared_secret,
        unsigned char* derived_key_out,
        const char context[8],
        uint64_t subkey_id = 1);

// Encrypt using ChaCha20-Poly1305 IETF mode
void encrypt_with_chacha20(
        const unsigned char* plaintext, unsigned long long plaintext_len,
        const unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
        unsigned char* ciphertext, unsigned long long* ciphertext_len,
        unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES]);

// Decrypt using ChaCha20-Poly1305 IETF mode
bool decrypt_with_chacha20(
        const unsigned char* ciphertext, unsigned long long ciphertext_len,
        const unsigned char key[crypto_aead_chacha20poly1305_ietf_KEYBYTES],
        const unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES],
        unsigned char* decrypted, unsigned long long* decrypted_len);

bool decrypt_dek(
        const std::vector<unsigned char>& encryptedDek,
        unsigned long long encryptedDekLen,
        const std::vector<unsigned char>& dekNonce,
        const unsigned char* derivedKey,
        std::vector<unsigned char>& decryptedDekOut
);

std::string base64Encode(const std::vector<unsigned char>& data);
std::vector<unsigned char> base64Decode(const std::string& encoded);