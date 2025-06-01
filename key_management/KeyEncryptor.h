#pragma once

#include <vector>
#include "keychain/keychain.h"
#include <string>


class KeyEncryptor {
public:
    struct EncryptedData {
        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> nonce;
    };
    KeyEncryptor(const std::string& package, const std::string& user);
    static EncryptedData encrypt(const std::vector<unsigned char>& plaintext,
                                 const std::vector<unsigned char>& kek);

    static std::vector<unsigned char> decrypt(const EncryptedData& encryptedData,
                                              const std::vector<unsigned char>& kek);


    void storeEncryptedKey(
        const std::string& keyName,
        const std::vector<unsigned char>& ciphertext,
        const std::vector<unsigned char>& nonce,
        keychain::Error& error
        );
    EncryptedData loadEncryptedKey(
        const std::string& keyName,
        keychain::Error& error);

private:
    // Private member variables to store the package and user for this instance
    const std::string package_;
    const std::string user_;
};


