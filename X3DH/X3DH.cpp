#include "x3dh.h"
#include "../crypto/crypto_utils.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

void run_x3dh_demo() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium." << std::endl;
        return;
    }

    unsigned char alice_eph_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_eph_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(alice_eph_pk, alice_eph_sk);
    print_hex("[Alice] Ephemeral Public Key: ", alice_eph_pk, sizeof(alice_eph_pk));

    unsigned char bob_id_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_id_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_id_pk, bob_id_sk);
    print_hex("[Bob] Identity Public Key: ", bob_id_pk, sizeof(bob_id_pk));

    unsigned char bob_spk_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_spk_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_spk_pk, bob_spk_sk);
    print_hex("[Bob] Signed Prekey Public Key: ", bob_spk_pk, sizeof(bob_spk_pk));

    unsigned char bob_opk_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_opk_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_opk_pk, bob_opk_sk);
    print_hex("[Bob] One-time Prekey Public Key: ", bob_opk_pk, sizeof(bob_opk_pk));

    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, alice_eph_sk, bob_id_pk) != 0 ||
        crypto_scalarmult(dh2, alice_eph_sk, bob_spk_pk) != 0 ||
        crypto_scalarmult(dh3, alice_eph_sk, bob_opk_pk) != 0) {
        std::cerr << "[Alice] Failed to compute DH values." << std::endl;
        return;
    }

    unsigned char alice_shared[crypto_generichash_BYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(alice_shared));
    crypto_generichash_update(&state, dh1, sizeof(dh1));
    crypto_generichash_update(&state, dh2, sizeof(dh2));
    crypto_generichash_update(&state, dh3, sizeof(dh3));
    crypto_generichash_final(&state, alice_shared, sizeof(alice_shared));
    print_hex("[Alice] Combined Shared Secret: ", alice_shared, sizeof(alice_shared));

    print_hex("[Bob] Received Alice's Ephemeral Public Key: ", alice_eph_pk, sizeof(alice_eph_pk));

    unsigned char bob_dh1[crypto_scalarmult_BYTES];
    unsigned char bob_dh2[crypto_scalarmult_BYTES];
    unsigned char bob_dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(bob_dh1, bob_id_sk, alice_eph_pk) != 0 ||
        crypto_scalarmult(bob_dh2, bob_spk_sk, alice_eph_pk) != 0 ||
        crypto_scalarmult(bob_dh3, bob_opk_sk, alice_eph_pk) != 0) {
        std::cerr << "[Bob] Failed to compute DH values." << std::endl;
        return;
    }

    unsigned char bob_shared[crypto_generichash_BYTES];
    crypto_generichash_init(&state, NULL, 0, sizeof(bob_shared));
    crypto_generichash_update(&state, bob_dh1, sizeof(bob_dh1));
    crypto_generichash_update(&state, bob_dh2, sizeof(bob_dh2));
    crypto_generichash_update(&state, bob_dh3, sizeof(bob_dh3));
    crypto_generichash_final(&state, bob_shared, sizeof(bob_shared));
    print_hex("[Bob] Combined Shared Secret: ", bob_shared, sizeof(bob_shared));

    if (memcmp(alice_shared, bob_shared, sizeof(alice_shared)) == 0) {
        std::cout << "[Success] Shared secrets match!" << std::endl;
    } else {
        std::cerr << "[Error] Shared secrets do not match!" << std::endl;
        return;
    }

    // Derive file encryption key from shared secret
    unsigned char file_key[crypto_aead_chacha20poly1305_ietf_KEYBYTES];
    if (!derive_key_from_shared_secret(
            alice_shared,
            file_key,
            "filekey0",
            1)) {
        std::cerr << "[Error] Failed to derive file encryption key." << std::endl;
        return;
    }
    print_hex("[Derived] File Encryption Key: ", file_key, sizeof(file_key));

    // Encrypt a test message
    const char* message = "secret file contents";
    unsigned long long message_len = strlen(message);

    unsigned char ciphertext[1024];
    unsigned long long ciphertext_len;

    unsigned char nonce[crypto_aead_chacha20poly1305_ietf_NPUBBYTES];

    encrypt_with_chacha20(
            (const unsigned char*)message, message_len,
            file_key,
            ciphertext, &ciphertext_len,
            nonce);

    // Decrypt the test message
    unsigned char decrypted[1024];
    unsigned long long decrypted_len;

    if (decrypt_with_chacha20(
            ciphertext, ciphertext_len,
            file_key,
            nonce,
            decrypted, &decrypted_len)) {
        decrypted[decrypted_len] = '\0'; // Null terminate
        std::cout << "Decrypted: " << decrypted << std::endl;
    } else {
        std::cerr << "[Error] Decryption failed." << std::endl;
    }
}
