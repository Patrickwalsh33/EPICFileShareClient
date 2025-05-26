#include "IdentityKeyPair.h"
#include <sodium.h>
#include <stdexcept>

IdentityKeyPair::IdentityKeyPair()
        : publicKey(crypto_box_PUBLICKEYBYTES), privateKey(crypto_box_SECRETKEYBYTES)
{
    if (crypto_box_keypair(publicKey.data(), privateKey.data()) != 0) {
        throw std::runtime_error("Failed to generate identity key pair");
    }
}

const std::vector<unsigned char>& IdentityKeyPair::getPublicKey() const {
    return publicKey;
}

const std::vector<unsigned char>& IdentityKeyPair::getPrivateKey() const {
    return privateKey;
}
