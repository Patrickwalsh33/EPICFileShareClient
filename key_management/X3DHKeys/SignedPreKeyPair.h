#pragma once

#include <vector>

//each key is 32 bytes long
class SignedPreKeyPair {
public:
    explicit SignedPreKeyPair(const std::vector<unsigned char>& identityPrivateSigningKey);

    //no discard throws a warning if we forget to use the return value
    [[nodiscard]] const std::vector<unsigned char>& getPublicKey() const;
    [[nodiscard]] const std::vector<unsigned char>& getPrivateKey() const;
    [[nodiscard]] const std::vector<unsigned char>& getSignature() const;

    static bool verifySignature(const std::vector<unsigned char>& identityPublicSigningKey,
                                const std::vector<unsigned char>& signedPrekeyPublic,
                                const std::vector<unsigned char>& signature);

private:
    std::vector<unsigned char> publicKey;
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> signature;
};



