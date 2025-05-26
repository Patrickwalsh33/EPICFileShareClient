#include "UserKeyGenerator.h"
#include <sodium.h>
#include <iostream>


UserKeyPair UserKeyGenerator::generateNewKeyPair()
{
    UserKeyPair keyPair;
    if (crypto_box_keypair(keyPair.public_key.data(), keyPair.secret_key.data()) != 0) {
        std::cerr << "Error: Failed to generate X25519 key pair." << std::endl;
        throw std::runtime_error("Failed to generate user key pair due to cryptographic error.");
    }
    return keyPair;
}
