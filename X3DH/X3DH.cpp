#include "X3DH.h"
#include "../crypto/crypto_utils.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

// Key classes
#include "../key_management/X3DHKeys/IdentityKeyPair.h"
#include "../key_management/X3DHKeys/EphemeralKeyPair.h"
#include "../key_management/X3DHKeys/SignedPreKeyPair.h"
#include "../key_management/X3DHKeys/OneTimeKeyPair.h"

void run_x3dh_demo() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium." << std::endl;
        return;
    }

    // === Sender ===
    EphemeralKeyPair senderEphemeral;
    print_hex("[Sender] Ephemeral Public Key: ", senderEphemeral.getPublicKey().data(), senderEphemeral.getPublicKey().size());

    // === Receiver ===
    IdentityKeyPair receiverIdentity;
    SignedPreKeyPair receiverSignedPre(receiverIdentity.getPrivateKey());
    OneTimeKeyPair receiverOneTime;

    unsigned char receiverCurveIdPriv[crypto_scalarmult_SCALARBYTES];
    unsigned char receiverCurveIdPub[crypto_scalarmult_BYTES];

    if (crypto_sign_ed25519_sk_to_curve25519(receiverCurveIdPriv, receiverIdentity.getPrivateKey().data()) != 0) {
        throw std::runtime_error("Failed to convert Ed25519 private key to Curve25519");
    }

    if (crypto_sign_ed25519_pk_to_curve25519(receiverCurveIdPub, receiverIdentity.getPublicKey().data()) != 0) {
        throw std::runtime_error("Failed to convert Ed25519 public key to Curve25519");
    }


    print_hex("[Receiver] Identity Public Key: ", receiverCurveIdPub, sizeof(receiverCurveIdPub));
    print_hex("[Receiver] Signed PreKey Public Key: ", receiverSignedPre.getPublicKey().data(), receiverSignedPre.getPublicKey().size());
    print_hex("[Receiver] One-Time PreKey Public Key: ", receiverOneTime.getPublicKey().data(), receiverOneTime.getPublicKey().size());
    print_hex("[Receiver] Signature on Signed PreKey: ", receiverSignedPre.getSignature().data(), receiverSignedPre.getSignature().size());

    // === Sender verifies receiver’s signed prekey ===
    if (crypto_sign_verify_detached(
            receiverSignedPre.getSignature().data(),
            receiverSignedPre.getPublicKey().data(),
            receiverSignedPre.getPublicKey().size(),
            receiverIdentity.getPublicKey().data()) != 0) {
        std::cerr << "[Sender] Signature verification on receiver's signed prekey FAILED!" << std::endl;
        return;
    }
    std::cout << "[Sender] Signature on receiver's signed prekey verified successfully." << std::endl;

    // === Sender computes shared secrets ===
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, senderEphemeral.getPrivateKey().data(), receiverCurveIdPub) != 0 ||
        crypto_scalarmult(dh2, senderEphemeral.getPrivateKey().data(), receiverSignedPre.getPublicKey().data()) != 0 ||
        crypto_scalarmult(dh3, senderEphemeral.getPrivateKey().data(), receiverOneTime.getPublicKey().data()) != 0) {
        std::cerr << "[Sender] Failed to compute DH values." << std::endl;
        return;
    }

    unsigned char senderShared[crypto_generichash_BYTES];
    crypto_generichash_state senderState;
    crypto_generichash_init(&senderState, NULL, 0, sizeof(senderShared));
    crypto_generichash_update(&senderState, dh1, sizeof(dh1));
    crypto_generichash_update(&senderState, dh2, sizeof(dh2));
    crypto_generichash_update(&senderState, dh3, sizeof(dh3));
    crypto_generichash_final(&senderState, senderShared, sizeof(senderShared));
    print_hex("[Sender] Combined Shared Secret: ", senderShared, sizeof(senderShared));

    // === Receiver computes shared secrets ===
    unsigned char dh1_recv[crypto_scalarmult_BYTES];
    unsigned char dh2_recv[crypto_scalarmult_BYTES];
    unsigned char dh3_recv[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1_recv, receiverCurveIdPriv, senderEphemeral.getPublicKey().data()) != 0 ||
        crypto_scalarmult(dh2_recv, receiverSignedPre.getPrivateKey().data(), senderEphemeral.getPublicKey().data()) != 0 ||
        crypto_scalarmult(dh3_recv, receiverOneTime.getPrivateKey().data(), senderEphemeral.getPublicKey().data()) != 0) {
        std::cerr << "[Receiver] Failed to compute DH values." << std::endl;
        return;
    }

    unsigned char receiverShared[crypto_generichash_BYTES];
    crypto_generichash_state receiverState;
    crypto_generichash_init(&receiverState, NULL, 0, sizeof(receiverShared));
    crypto_generichash_update(&receiverState, dh1_recv, sizeof(dh1_recv));
    crypto_generichash_update(&receiverState, dh2_recv, sizeof(dh2_recv));
    crypto_generichash_update(&receiverState, dh3_recv, sizeof(dh3_recv));
    crypto_generichash_final(&receiverState, receiverShared, sizeof(receiverShared));
    print_hex("[Receiver] Combined Shared Secret: ", receiverShared, sizeof(receiverShared));

    // === Compare shared secrets ===
    if (memcmp(senderShared, receiverShared, sizeof(senderShared)) == 0) {
        std::cout << "[SUCCESS] Shared secrets match." << std::endl;
    } else {
        std::cerr << "[ERROR] Shared secrets DO NOT match." << std::endl;
        return;
    }

    // === Derive file encryption key from shared secret ===
    unsigned char fileKey[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    if (!derive_key_from_shared_secret(senderShared, fileKey, "filekey0", 1)) {
        std::cerr << "[ERROR] Failed to derive file key." << std::endl;
        return;
    }
    print_hex("[Derived] File Encryption Key: ", fileKey, sizeof(fileKey));

    // === Encrypt a test message ===
    const char* message = "secret file contents";
    unsigned long long messageLen = strlen(message);

    unsigned char ciphertext[1024];
    unsigned long long ciphertextLen;

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

    encrypt_with_chacha20(
            reinterpret_cast<const unsigned char*>(message),
            messageLen,
            fileKey,
            ciphertext,
            &ciphertextLen,
            nonce
    );

    // === Decrypt the message ===
    unsigned char decrypted[1024];
    unsigned long long decryptedLen;

    if (decrypt_with_chacha20(
            ciphertext, ciphertextLen,
            fileKey,
            nonce,
            decrypted, &decryptedLen)) {
        decrypted[decryptedLen] = '\0';
        std::cout << "Decrypted: " << decrypted << std::endl;
    } else {
        std::cerr << "[ERROR] Decryption failed." << std::endl;
    }
}
