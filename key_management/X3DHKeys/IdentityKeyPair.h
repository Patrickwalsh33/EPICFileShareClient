#pragma once
#include <vector>

class IdentityKeyPair {
public:
    IdentityKeyPair();

    //no discard throws a warning if we forget to use the return value
    [[nodiscard]] const std::vector<unsigned char>& getPublicKey() const;
    [[nodiscard]] const std::vector<unsigned char>& getPrivateKey() const;

private:
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
};


