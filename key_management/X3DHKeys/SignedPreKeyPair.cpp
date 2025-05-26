#include "SignedPreKeyPair.h"
#include <sodium.h>
#include <stdexcept>

SignedPreKeyPair::SignedPreKeyPair(const std::vector<unsigned char>& identityPrivateSigningKey)
        : publicKey(crypto_box_PUBLICKEYBYTES),
          privateKey(crypto_box_SECRETKEYBYTES),
          signature(crypto_sign_BYTES)
{
    // Generate the prekey pair
    crypto_box_keypair(publicKey.data(), privateKey.data());

    // Sign the public prekey using the private identity key
    if (identityPrivateSigningKey.size() != crypto_sign_SECRETKEYBYTES) {
        throw std::runtime_error("Invalid identity private signing key size.");
    }

    unsigned long long sig_len;
    crypto_sign_detached(signature.data(), &sig_len,
                         publicKey.data(), publicKey.size(),
                         identityPrivateSigningKey.data());
}

const std::vector<unsigned char>& SignedPreKeyPair::getPublicKey() const {
    return publicKey;
}

const std::vector<unsigned char>& SignedPreKeyPair::getPrivateKey() const {
    return privateKey;
}

const std::vector<unsigned char>& SignedPreKeyPair::getSignature() const {
    return signature;
}

bool SignedPreKeyPair::verifySignature(const std::vector<unsigned char>& identityPublicSigningKey,
                                       const std::vector<unsigned char>& signedPrekeyPublic,
                                       const std::vector<unsigned char>& signature) {
    if (identityPublicSigningKey.size() != crypto_sign_PUBLICKEYBYTES ||
        signedPrekeyPublic.size() != crypto_box_PUBLICKEYBYTES ||
        signature.size() != crypto_sign_BYTES) {
        return false;
    }

    return crypto_sign_verify_detached(signature.data(),
                                       signedPrekeyPublic.data(), signedPrekeyPublic.size(),
                                       identityPublicSigningKey.data()) == 0;
}