//
// Created by Tóla Bowen Maccurtain on 22/05/2025.
//

#ifndef ENCRYPTIONKEYGENERATOR_H
#define ENCRYPTIONKEYGENERATOR_H
#include <vector>

const size_t Encryption_KEY_SIZE = 32;



class EncryptionKeyGenerator
{
public:
    static std::vector<unsigned char> generateKey(size_t key_bytes);


private:

    EncryptionKeyGenerator() = delete;
    EncryptionKeyGenerator(const EncryptionKeyGenerator&) = delete;
    EncryptionKeyGenerator& operator=(const EncryptionKeyGenerator&) = delete;
};

#endif //ENCRYPTIONKEYGENERATOR_H
