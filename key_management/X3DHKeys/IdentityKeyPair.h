#pragma once
#include <vector>

class IdentityKeyPair {
public:
    IdentityKeyPair();

    [[nodiscard]] const std::vector<unsigned char>& getPublicKey() const;
    [[nodiscard]] const std::vector<unsigned char>& getPrivateKey() const;

private:
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
};


