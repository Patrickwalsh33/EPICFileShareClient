#pragma once
#include <vector>
#include "EncryptionKeyGenerator.h"
static const int DEFAULT_ONETIME_KEYS = 10;

struct DecryptedKeyData {
    std::vector<unsigned char> identityPrivateKey;
    std::vector<unsigned char> signedPreKeyPrivate;
    std::vector<unsigned char> oneTimeKeyPrivate;
    std::vector<std::vector<unsigned char>> oneTimeKeyPrivates; // Now a vector of keys
};

struct OneTimeKeyData {
    std::vector<unsigned char> privateKey;
    std::vector<unsigned char> publicKey;
    int keyId; // For tracking which key this is
};


class KEKManager {

    EncryptionKeyGenerator* keyGenerator;
public:
    static std::vector<unsigned char> encryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek,std::vector<unsigned char>& nonceOut);
    static std::vector<unsigned char> decryptKEK(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& kek, const std::vector<unsigned char>& nonce);
    static void generateAndStoreUserKeys(const std::vector<unsigned char>& kek, int numOneTimeKeys = DEFAULT_ONETIME_KEYS);
    static DecryptedKeyData decryptStoredUserKeys(const std::vector<unsigned char>& kek);

    static std::vector<OneTimeKeyData> generateOneTimeKeys(int count);
    static void storeOneTimeKeys(const std::vector<OneTimeKeyData>& keys, const std::vector<unsigned char>& kek);
    static std::vector<OneTimeKeyData> loadOneTimeKeys(const std::vector<unsigned char>& kek);
    static void removeUsedOneTimeKey(int keyId);
};
