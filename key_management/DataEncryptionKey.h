#pragma once

#include <vector>

class DataEncryptionKey {
public:
    DataEncryptionKey();  // generates random key
    ~DataEncryptionKey(); // clears key from memory

    [[nodiscard]] const std::vector<unsigned char>& getKey() const;

private:
    std::vector<unsigned char> key;
    void secureZero(); // internal cleanup
};



