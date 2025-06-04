#include "OneTimeKeyPair.h"
#include <sodium.h>

//each key is 32 bytes long
OneTimeKeyPair::OneTimeKeyPair()
        : publicKey(crypto_box_PUBLICKEYBYTES), privateKey(crypto_box_SECRETKEYBYTES)
{
    crypto_box_keypair(publicKey.data(), privateKey.data());
}

const std::vector<unsigned char>& OneTimeKeyPair::getPublicKey() const {
    return publicKey;
}

const std::vector<unsigned char>& OneTimeKeyPair::getPrivateKey() const {
    return privateKey;
}
