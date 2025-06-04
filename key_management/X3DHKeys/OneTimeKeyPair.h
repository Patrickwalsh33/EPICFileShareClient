#pragma once

#include <vector>

class OneTimeKeyPair {
public:
    OneTimeKeyPair();  // Generates a one-time key pair upon construction

    //no discard throws a warning if we forget to use the return value
    [[nodiscard]] const std::vector<unsigned char>& getPublicKey() const;
    [[nodiscard]] const std::vector<unsigned char>& getPrivateKey() const;

private:
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
};



