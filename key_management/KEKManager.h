#pragma once
#include <vector>
#include "EncryptionKeyGenerator.h"


class KEKManager {

    EncryptionKeyGenerator* keyGenerator;
public:
    static std::vector<unsigned char> encryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek,std::vector<unsigned char>& nonceOut);
    static std::vector<unsigned char> decryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek, const std::vector<unsigned char>& nonce);
    static void generateAndStoreUserKeys(const std::vector<unsigned char>& kek);
    static void decryptAndStoredUserKeys(const std::vector<unsigned char>& kek);


};
