#pragma once

#include <vector>

class SignedPreKeyPair {
public:
    explicit SignedPreKeyPair(const std::vector<unsigned char>& identityPrivateSigningKey);

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



