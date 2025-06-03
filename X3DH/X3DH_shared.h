#pragma once
#include <cstddef>
#include <sodium.h>

// Sender: Derive shared secret using own Ed25519 identity key and receiver's public keys
bool x3dh_sender_derive_shared_secret(
        unsigned char* outSharedSecret,
        size_t outLen,
        const unsigned char senderEphemeralPriv[crypto_scalarmult_SCALARBYTES],
        const unsigned char senderIdentityPrivEd[crypto_sign_SECRETKEYBYTES],
        const unsigned char receiverIdentityPubEd[crypto_sign_PUBLICKEYBYTES],
        const unsigned char receiverIdentityPubCurve[crypto_scalarmult_BYTES],
        const unsigned char receiverSignedPrekeyPub[crypto_scalarmult_BYTES],
        const unsigned char receiverSignedPrekeySig[crypto_sign_BYTES]
);

// Receiver: Derive shared secret using sender's public keys and own Ed25519 identity private key
bool x3dh_receiver_derive_shared_secret(
        unsigned char* outSharedSecret,
        size_t outLen,
        const unsigned char senderEphemeralPub[crypto_scalarmult_BYTES],
        const unsigned char senderIdentityPubEd[crypto_sign_PUBLICKEYBYTES],
        const unsigned char receiverIdentityPrivEd[crypto_sign_SECRETKEYBYTES],
        const unsigned char receiverSignedPrekeyPriv[crypto_scalarmult_SCALARBYTES]
);
