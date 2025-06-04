#include "EphemeralKeyPair.h"
#include <sodium.h>

//each key is 32 bytes long
EphemeralKeyPair::EphemeralKeyPair()
        : publicKey(crypto_box_PUBLICKEYBYTES), privateKey(crypto_box_SECRETKEYBYTES)
{
    crypto_box_keypair(publicKey.data(), privateKey.data());
}

const std::vector<unsigned char>& EphemeralKeyPair::getPublicKey() const {
    return publicKey;
}

const std::vector<unsigned char>& EphemeralKeyPair::getPrivateKey() const {
    return privateKey;
}
