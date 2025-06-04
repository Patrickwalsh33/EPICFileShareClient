#include "IdentityKeyPair.h"
#include <sodium.h>
#include <stdexcept>

//each key is 32 bytes long
IdentityKeyPair::IdentityKeyPair()
        : publicKey(crypto_sign_PUBLICKEYBYTES), privateKey(crypto_sign_SECRETKEYBYTES)
{
    if (crypto_sign_keypair(publicKey.data(), privateKey.data()) != 0) {
        throw std::runtime_error("Failed to generate identity signing key pair");
    }
}

const std::vector<unsigned char>& IdentityKeyPair::getPublicKey() const {
    return publicKey;
}

const std::vector<unsigned char>& IdentityKeyPair::getPrivateKey() const {
    return privateKey;
}
