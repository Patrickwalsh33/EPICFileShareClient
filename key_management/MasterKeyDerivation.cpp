#include "MasterKeyDerivation.h"
#include <sodium/core.h>
#include <sodium/crypto_pwhash.h>
#include <sodium.h>
#include <stdexcept>

MasterKeyDerivation::MasterKeyDerivation() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

MasterKeyDerivation::~MasterKeyDerivation() = default;



std::vector<unsigned char> MasterKeyDerivation::deriveMaster(
    const std::string& password,
    const std::vector<unsigned char>& salt
    ) {

    std::vector<unsigned char> masterKey(crypto_aead_chacha20poly1305_ietf_KEYBYTES);

    if (crypto_pwhash(
        masterKey.data(),
        masterKey.size(),
        password.c_str(),
        password.size(),
        salt.data(),
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE,
        crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("Master Derivation failed");
            }

    return masterKey;
}

bool MasterKeyDerivation::verifyMaster(const std::string& hash, const std::string& password) {
    return crypto_pwhash_str_verify(
               hash.c_str(),
               password.c_str(),
               password.size()) == 0;
}