#include "MasterKeyDerivation.h"
#include <sodium/core.h>
#include <sodium/crypto_pwhash.h>
#include <stdexcept>

MasterKeyDerivation::MasterKeyDerivation() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

MasterKeyDerivation::~MasterKeyDerivation() = default;



std::string MasterKeyDerivation::deriveMaster(const std::string& password) {
    char hash[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str(
            hash,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        throw std::runtime_error("Master Derivation failed");
            }

    return std::string(hash);
}

bool MasterKeyDerivation::verifyMaster(const std::string& hash, const std::string& password) {
    return crypto_pwhash_str_verify(
               hash.c_str(),
               password.c_str(),
               password.size()) == 0;
}