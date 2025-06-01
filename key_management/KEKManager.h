#pragma once
#include <vector>
#include "EncryptionKeyGenerator.h"
#include "KeyEncryptor.h"


class KEKManager {
    KEKManager(const std::string& package, const std::string& user);
    EncryptionKeyGenerator* keyGenerator;
public:
    void encryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek,std::vector<unsigned char>& nonceOut);
    static std::vector<unsigned char> decryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek, const std::vector<unsigned char>& nonce);
    void generateAndStoreUserKeys(const std::vector<unsigned char>& kek);
    void decryptStoredUserKeys(const std::vector<unsigned char>& kek);
private:
    KeyEncryptor keyEncryptor_;

};
