//
// Created by Tóla Bowen Maccurtain on 20/05/2025.
//

#include "PasswordHashing.h"
#include <sodium.h>
#include <stdexcept>
#include <string>
#include <iostream>

PasswordHashing::PasswordHashing() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }
}

PasswordHashing::~PasswordHashing() = default;



std::string PasswordHashing::hashPassword(const std::string& password) {
    char hash[crypto_pwhash_STRBYTES];

    if (crypto_pwhash_str(
            hash,
            password.c_str(),
            password.size(),
            crypto_pwhash_OPSLIMIT_MODERATE,
            crypto_pwhash_MEMLIMIT_MODERATE) != 0) {
        throw std::runtime_error("Password hashing failed");
            }

    return std::string(hash);
}

bool PasswordHashing::verifyPassword(const std::string& hash, const std::string& password) {
    return crypto_pwhash_str_verify(
               hash.c_str(),
               password.c_str(),
               password.size()) == 0;
}
