//#include "../X3DH/X3DH_shared.h"
//#include "../crypto/crypto_utils.h"
//#include <sodium.h>
//#include <iostream>
//#include <cstring>
//
//void test_file_encryption_flow() {
//    unsigned char sharedSecret[crypto_generichash_BYTES];
//
//    if (!run_x3dh(sharedSecret, sizeof(sharedSecret))) {
//        std::cerr << "[TEST] X3DH failed, cannot proceed with encryption test." << std::endl;
//        return;
//    }
//
//    // Derive key from shared secret
//    unsigned char fileKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
//    if (!derive_key_from_shared_secret(sharedSecret, fileKey, "filekey0", 1)) {
//        std::cerr << "[TEST] Failed to derive file key." << std::endl;
//        return;
//    }
//
//    print_hex("[TEST] Derived File Key: ", fileKey, sizeof(fileKey));
//
//    // Encrypt test message
//    const char* message = "secret file contents";
//    unsigned char ciphertext[1024], nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];
//    unsigned long long ciphertextLen;
//
//    encrypt_with_chacha20(reinterpret_cast<const unsigned char*>(message), strlen(message),
//                          fileKey, ciphertext, &ciphertextLen, nonce);
//
//    // Decrypt
//    unsigned char decrypted[1024];
//    unsigned long long decryptedLen;
//
//    if (decrypt_with_chacha20(ciphertext, ciphertextLen, fileKey, nonce, decrypted, &decryptedLen)) {
//        decrypted[decryptedLen] = '\0';
//        std::cout << "[TEST] Decrypted: " << decrypted << std::endl;
//    } else {
//        std::cerr << "[TEST] Decryption failed." << std::endl;
//    }
//}
//
