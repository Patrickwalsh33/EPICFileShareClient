#pragma once
#include <vector>
#include "EncryptionKeyGenerator.h"


class KEKManager {

    EncryptionKeyGenerator* keyGenerator;
public:
    std::vector<unsigned char> encryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek,std::vector<unsigned char>& nonceOut);
    std::vector<unsigned char> decryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek, std::vector<unsigned char>& nonce);

};
