#include "X3DH_shared.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

bool x3dh_receiver_derive_shared_secret(
        unsigned char* outSharedSecret,
        size_t outLen,
        const unsigned char senderEphemeralPub[crypto_scalarmult_BYTES],
        const unsigned char senderIdentityPubEd[crypto_sign_PUBLICKEYBYTES],
        const unsigned char receiverIdentityPrivEd[crypto_sign_SECRETKEYBYTES],
        const unsigned char receiverSignedPrekeyPriv[crypto_scalarmult_SCALARBYTES]
) {
    if (sodium_init() < 0) {
        std::cerr << "[X3DH] libsodium initialization failed." << std::endl;
        return false;
    }

    // === Convert sender identity public key to Curve25519 ===
    unsigned char senderIdentityPubCurve[crypto_scalarmult_BYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(senderIdentityPubCurve, senderIdentityPubEd) != 0) {
        std::cerr << "[X3DH] Failed to convert sender identity Ed25519 pubkey to Curve25519." << std::endl;
        return false;
    }

    // === Convert receiver identity private key to Curve25519 ===
    unsigned char receiverIdentityPrivCurve[crypto_scalarmult_SCALARBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(receiverIdentityPrivCurve, receiverIdentityPrivEd) != 0) {
        std::cerr << "[X3DH] Failed to convert receiver identity Ed25519 secret key to Curve25519." << std::endl;
        return false;
    }

    // === Perform 3 DHs ===
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, receiverIdentityPrivCurve, senderEphemeralPub) != 0 ||
        crypto_scalarmult(dh2, receiverSignedPrekeyPriv, senderEphemeralPub) != 0 ||
        crypto_scalarmult(dh3, receiverSignedPrekeyPriv, senderIdentityPubCurve) != 0) {
        std::cerr << "[X3DH Receiver] Failed to compute DH values." << std::endl;
        return false;
    }

    // === KDF ===
    unsigned char combined[crypto_generichash_BYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(combined));
    crypto_generichash_update(&state, dh1, sizeof(dh1));
    crypto_generichash_update(&state, dh2, sizeof(dh2));
    crypto_generichash_update(&state, dh3, sizeof(dh3));
    crypto_generichash_final(&state, combined, sizeof(combined));

    if (outLen < sizeof(combined)) {
        std::cerr << "[X3DH Receiver] Output buffer too small." << std::endl;
        return false;
    }

    std::memcpy(outSharedSecret, combined, sizeof(combined));
    return true;
}
