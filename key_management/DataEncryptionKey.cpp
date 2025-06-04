#include "DataEncryptionKey.h"
#include <sodium.h>
#include <stdexcept>

DataEncryptionKey::DataEncryptionKey()
        : key(crypto_aead_chacha20poly1305_ietf_KEYBYTES)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    //uses libsodiums cryptographically secure random number generator
    randombytes_buf(key.data(), key.size());
}

DataEncryptionKey::~DataEncryptionKey() {
    secureZero();
}

const std::vector<unsigned char>& DataEncryptionKey::getKey() const {
    return key;
}

void DataEncryptionKey::secureZero() {
    sodium_memzero(key.data(), key.size());
}
