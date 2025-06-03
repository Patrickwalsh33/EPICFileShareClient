#pragma once

#include <vector>

class DataEncryptionKey {
public:
    DataEncryptionKey();
    ~DataEncryptionKey();

    [[nodiscard]] const std::vector<unsigned char>& getKey() const;

private:
    std::vector<unsigned char> key;
    void secureZero();
};



