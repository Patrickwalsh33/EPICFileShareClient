#include "X3DH_shared.h"
#include <sodium.h>
#include <cstring>
#include <iostream>

bool x3dh_sender_derive_shared_secret(
        unsigned char* outSharedSecret,
        size_t outLen,
        const unsigned char senderEphemeralPriv[crypto_scalarmult_SCALARBYTES],
        const unsigned char senderIdentityPrivEd[crypto_sign_SECRETKEYBYTES],
        const unsigned char receiverIdentityPubEd[crypto_sign_PUBLICKEYBYTES],
        const unsigned char receiverSignedPrekeyPub[crypto_scalarmult_BYTES],
        const unsigned char receiverSignedPrekeySig[crypto_sign_BYTES]
) {
    if (sodium_init() < 0) {
        std::cerr << "[X3DH] libsodium initialization failed." << std::endl;
        return false;
    }

    //Verify signed prekey signature
    if (crypto_sign_verify_detached(
            receiverSignedPrekeySig,
            receiverSignedPrekeyPub,
            crypto_scalarmult_BYTES,
            receiverIdentityPubEd
    ) != 0) {
        std::cerr << "[X3DH] Signature verification on signed prekey FAILED!" << std::endl;
        return false;
    }

    std::cout << "[X3DH] Signed prekey signature verified." << std::endl;

    // Convert sender identity Ed25519 key to Curve25519
    unsigned char senderIdentityPrivCurve[crypto_scalarmult_SCALARBYTES];
    if (crypto_sign_ed25519_sk_to_curve25519(senderIdentityPrivCurve, senderIdentityPrivEd) != 0) {
        std::cerr << "[X3DH] Failed to convert Ed25519 secret key to Curve25519." << std::endl;
        return false;
    }

    // Convert receiver identity Ed25519 public key to Curve25519
    unsigned char receiverIdentityPubCurve[crypto_scalarmult_BYTES];
    if (crypto_sign_ed25519_pk_to_curve25519(receiverIdentityPubCurve, receiverIdentityPubEd) != 0) {
        std::cerr << "[X3DH] Failed to convert receiver Ed25519 public key to Curve25519." << std::endl;
        return false;
    }

    // Perform 3 DHs
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, senderEphemeralPriv, receiverIdentityPubCurve) != 0 ||
        crypto_scalarmult(dh2, senderEphemeralPriv, receiverSignedPrekeyPub) != 0 ||
        crypto_scalarmult(dh3, senderIdentityPrivCurve, receiverSignedPrekeyPub) != 0) {
        std::cerr << "[X3DH] Failed to compute DH values." << std::endl;
        return false;
    }

    // Derive shared secret with KDF (Blake2b)
    unsigned char combined[crypto_generichash_BYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(combined));
    crypto_generichash_update(&state, dh1, sizeof(dh1));
    crypto_generichash_update(&state, dh2, sizeof(dh2));
    crypto_generichash_update(&state, dh3, sizeof(dh3));
    crypto_generichash_final(&state, combined, sizeof(combined));

    //checks size of output buffer, protects from buffer overflow
    if (outLen < sizeof(combined)) {
        std::cerr << "[X3DH] Output buffer too small." << std::endl;
        return false;
    }

    std::memcpy(outSharedSecret, combined, sizeof(combined));
    return true;
}
