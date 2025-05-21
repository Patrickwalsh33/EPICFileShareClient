#include <sodium.h>
#include <iostream>
#include <cstring>

void print_hex(const char* label, const unsigned char* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    std::cout << std::endl;
}

int main() {
    if (sodium_init() < 0) {
        std::cerr << "Failed to initialize libsodium." << std::endl;
        return 1;
    }

    // Generate Alice's ephemeral key pair
    unsigned char alice_eph_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char alice_eph_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(alice_eph_pk, alice_eph_sk);
    print_hex("[Alice] Ephemeral Public Key: ", alice_eph_pk, sizeof(alice_eph_pk));

    // Bob's Identity Key
    unsigned char bob_id_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_id_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_id_pk, bob_id_sk);
    print_hex("[Bob] Identity Public Key: ", bob_id_pk, sizeof(bob_id_pk));

    // Bob's Signed Prekey
    unsigned char bob_spk_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_spk_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_spk_pk, bob_spk_sk);
    print_hex("[Bob] Signed Prekey Public Key: ", bob_spk_pk, sizeof(bob_spk_pk));

    // Bob's One-time Prekey
    unsigned char bob_opk_pk[crypto_box_PUBLICKEYBYTES];
    unsigned char bob_opk_sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(bob_opk_pk, bob_opk_sk);
    print_hex("[Bob] One-time Prekey Public Key: ", bob_opk_pk, sizeof(bob_opk_pk));

    // Alice computes shared secrets
    unsigned char dh1[crypto_scalarmult_BYTES];
    unsigned char dh2[crypto_scalarmult_BYTES];
    unsigned char dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(dh1, alice_eph_sk, bob_id_pk) != 0) {
        std::cerr << "[Alice] Failed to compute DH1" << std::endl;
        return 1;
    }
    if (crypto_scalarmult(dh2, alice_eph_sk, bob_spk_pk) != 0) {
        std::cerr << "[Alice] Failed to compute DH2" << std::endl;
        return 1;
    }
    if (crypto_scalarmult(dh3, alice_eph_sk, bob_opk_pk) != 0) {
        std::cerr << "[Alice] Failed to compute DH3" << std::endl;
        return 1;
    }

    // Combine shared secrets (simplified version)
    unsigned char alice_shared[crypto_generichash_BYTES];
    crypto_generichash_state state;
    crypto_generichash_init(&state, NULL, 0, sizeof(alice_shared));
    crypto_generichash_update(&state, dh1, sizeof(dh1));
    crypto_generichash_update(&state, dh2, sizeof(dh2));
    crypto_generichash_update(&state, dh3, sizeof(dh3));
    crypto_generichash_final(&state, alice_shared, sizeof(alice_shared));
    print_hex("[Alice] Combined Shared Secret: ", alice_shared, sizeof(alice_shared));

    // Bob simulates Alice's ephemeral public key
    print_hex("[Bob] Received Alice's Ephemeral Public Key: ", alice_eph_pk, sizeof(alice_eph_pk));

    unsigned char bob_dh1[crypto_scalarmult_BYTES];
    unsigned char bob_dh2[crypto_scalarmult_BYTES];
    unsigned char bob_dh3[crypto_scalarmult_BYTES];

    if (crypto_scalarmult(bob_dh1, bob_id_sk, alice_eph_pk) != 0) {
        std::cerr << "[Bob] Failed to compute DH1" << std::endl;
        return 1;
    }
    if (crypto_scalarmult(bob_dh2, bob_spk_sk, alice_eph_pk) != 0) {
        std::cerr << "[Bob] Failed to compute DH2" << std::endl;
        return 1;
    }
    if (crypto_scalarmult(bob_dh3, bob_opk_sk, alice_eph_pk) != 0) {
        std::cerr << "[Bob] Failed to compute DH3" << std::endl;
        return 1;
    }

    unsigned char bob_shared[crypto_generichash_BYTES];
    crypto_generichash_init(&state, NULL, 0, sizeof(bob_shared));
    crypto_generichash_update(&state, bob_dh1, sizeof(bob_dh1));
    crypto_generichash_update(&state, bob_dh2, sizeof(bob_dh2));
    crypto_generichash_update(&state, bob_dh3, sizeof(bob_dh3));
    crypto_generichash_final(&state, bob_shared, sizeof(bob_shared));
    print_hex("[Bob] Combined Shared Secret: ", bob_shared, sizeof(bob_shared));

    // Check if both secrets match
    if (memcmp(alice_shared, bob_shared, sizeof(alice_shared)) == 0) {
        std::cout << "[Success] Shared secrets match!" << std::endl;
    } else {
        std::cerr << "[Error] Shared secrets do not match!" << std::endl;
        return 1;
    }

    return 0;
}
