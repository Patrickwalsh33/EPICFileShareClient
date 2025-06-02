#include "X3DH.h"
#include "../crypto/crypto_utils.h"
#include <sodium.h>
#include <iostream>
#include <cstring>
#include "../key_management/X3DHKeys/EphemeralKeyPair.h"


bool run_x3dh(unsigned char* outSharedSecret, size_t outLen) {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium." << std::endl;
        return false;
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
        std::cerr << "Failed to convert Ed25519 private key to Curve25519" << std::endl;
        return false;
    }

    if (crypto_sign_ed25519_pk_to_curve25519(receiverCurveIdPub, receiverIdentity.getPublicKey().data()) != 0) {
        std::cerr << "Failed to convert Ed25519 public key to Curve25519" << std::endl;
        return false;
    }

    print_hex("[Receiver] Identity Public Key: ", receiverCurveIdPub, sizeof(receiverCurveIdPub));
    print_hex("[Receiver] Signed PreKey Public Key: ", receiverSignedPre.getPublicKey().data(), receiverSignedPre.getPublicKey().size());
    print_hex("[Receiver] One-Time PreKey Public Key: ", receiverOneTime.getPublicKey().data(), receiverOneTime.getPublicKey().size());
    print_hex("[Receiver] Signature on Signed PreKey: ", receiverSignedPre.getSignature().data(), receiverSignedPre.getSignature().size());

    // === Verify signature ===
    if (crypto_sign_verify_detached(
            receiverSignedPre.getSignature().data(),
            receiverSignedPre.getPublicKey().data(),
            receiverSignedPre.getPublicKey().size(),
            receiverIdentity.getPublicKey().data()) != 0) {
        std::cerr << "[Sender] Signature verification on receiver's signed prekey FAILED!" << std::endl;
        return false;
    }

    std::cout << "[Sender] Signature on receiver's signed prekey verified successfully." << std::endl;

    // === DH Computation ===
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, senderEphemeral.getPrivateKey().data(), receiverCurveIdPub) != 0 ||
        crypto_scalarmult(dh2, senderEphemeral.getPrivateKey().data(), receiverSignedPre.getPublicKey().data()) != 0 ||
        crypto_scalarmult(dh3, senderEphemeral.getPrivateKey().data(), receiverOneTime.getPublicKey().data()) != 0) {
        std::cerr << "[Sender] Failed to compute DH values." << std::endl;
        return false;
    }

    unsigned char senderShared[crypto_generichash_BYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(senderShared));
    crypto_generichash_update(&state, dh1, sizeof(dh1));
    crypto_generichash_update(&state, dh2, sizeof(dh2));
    crypto_generichash_update(&state, dh3, sizeof(dh3));
    crypto_generichash_final(&state, senderShared, sizeof(senderShared));
    print_hex("[Sender] Combined Shared Secret: ", senderShared, sizeof(senderShared));

    if (outLen < sizeof(senderShared)) {
        std::cerr << "[X3DH] Output buffer too small to hold shared secret." << std::endl;
        return false;
    }

    std::memcpy(outSharedSecret, senderShared, sizeof(senderShared));
    return true;
}
