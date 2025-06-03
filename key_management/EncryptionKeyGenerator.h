#pragma once
#include <vector>

const size_t Encryption_KEY_SIZE = 32;



class EncryptionKeyGenerator {
public:
    static std::vector<unsigned char> generateKey(size_t key_bytes);

    EncryptionKeyGenerator() = delete;
    EncryptionKeyGenerator(const EncryptionKeyGenerator &) = delete;
    EncryptionKeyGenerator &operator=(const EncryptionKeyGenerator &) = delete; //C++ operator overloading

};
