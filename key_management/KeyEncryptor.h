#pragma once

#include <vector>

class KeyEncryptor {
public:
    struct EncryptedData {
        std::vector<unsigned char> ciphertext;
        std::vector<unsigned char> nonce;
    };

    static EncryptedData encrypt(const std::vector<unsigned char>& plaintext,
                                 const std::vector<unsigned char>& kek);

    static std::vector<unsigned char> decrypt(const EncryptedData& encryptedData,
                                              const std::vector<unsigned char>& kek);
};

