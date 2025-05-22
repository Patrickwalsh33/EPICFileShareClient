#include "x3dh.h"
#include <sodium.h>
#include <iostream>
#include <cstring>

void print_hex(const char* label, const unsigned char* data, size_t len) {
    std::cout << label;
    for (size_t i = 0; i < len; i++)
        printf("%02x", data[i]);
    std::cout << std::endl;
}

void run_x3dh_demo() {
    if (sodium_init() < 0) {
// std::cerr is the error output stream, different from std::cout
// it still lets you print to the console, but it's used for error messages
// so hypothetically we could redirect all output in std::cerr to a file,
// and all output in std::cout to the console, so we could clearly see which is which

        std::cerr << "Failed to initialize libsodium." << std::endl;
        return;
    }

// first 2 lines here are creating arrays of unsigned chars that the result of the
// crypto_box_keypair function will be stored in
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


    //crypto_scalarmult is a function that computes a Diffie-Hellman shared secret
    //it multiplies the scalar * point (algo = Curve25519)
    //the first argument is the result, the second is the scalar, and the third is the point
    //if any of the functions fail, it will return a non-zero value
    //first one if for authentication
    if (crypto_scalarmult(dh1, alice_eph_sk, bob_id_pk) != 0 ||
        //second one is for forward secrecy and resistance to replay attacks
        crypto_scalarmult(dh2, alice_eph_sk, bob_spk_pk) != 0 ||
        //adds secrecy against compromise of long term id keys
        crypto_scalarmult(dh3, alice_eph_sk, bob_opk_pk) != 0) {
        std::cerr << "[Alice] Failed to compute DH values." << std::endl;
        return;
    }

    unsigned char alice_shared[crypto_generichash_BYTES];
    //structure that holds the state of the BLAKE2b hash function
    crypto_generichash_state state;
    //initialise the state
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


    //should switch to crypto_verify_32
    if (memcmp(alice_shared, bob_shared, sizeof(alice_shared)) == 0) {
        std::cout << "[Success] Shared secrets match!" << std::endl;
    } else {
        std::cerr << "[Error] Shared secrets do not match!" << std::endl;
    }
}
