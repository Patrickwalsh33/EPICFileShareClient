#include "X3DH_Shared.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

bool x3dh_receiver_derive_shared_secret(
        unsigned char* outSharedSecret,
        size_t outLen,
        const unsigned char senderEphemeralPub[crypto_scalarmult_BYTES],
        const unsigned char receiverIdentityPrivCurve[crypto_scalarmult_SCALARBYTES],
        const unsigned char receiverSignedPrekeyPriv[crypto_scalarmult_SCALARBYTES],
        const unsigned char receiverOneTimePrekeyPriv[crypto_scalarmult_SCALARBYTES]
) {
    if (sodium_init() < 0) {
        std::cerr << "[X3DH] libsodium initialization failed." << std::endl;
        return false;
    }

    // === DH Computation ===
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, receiverIdentityPrivCurve, senderEphemeralPub) != 0 ||
        crypto_scalarmult(dh2, receiverSignedPrekeyPriv, senderEphemeralPub) != 0 ||
        crypto_scalarmult(dh3, receiverOneTimePrekeyPriv, senderEphemeralPub) != 0) {
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

