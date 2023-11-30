#include "crypto-suites/crypto-curve/ed25519_ex.h"

#include "third_party/ed25519-donna/ed25519-donna.h"
#include "third_party/ed25519-donna/ed25519-donna-memzero.h"
#define memzero ed25519_donna_memzero

void
ed25519_publickey_pure (const ed25519_secret_key sk, ed25519_public_key pk) {
    bignum256modm a = {0};
    ge25519 ALIGN(16) A;

    /* A = aB */
    expand256_modm(a, sk, 32);
    ge25519_scalarmult_base_niels(&A, ge25519_niels_base_multiples, a);
    memzero(&a, sizeof(a));
    ge25519_pack(pk, &A);
}


int
ed25519_publickey_neg (ed25519_public_key res, const ed25519_public_key pk){
    ge25519 ALIGN(16) P;

    if (!ge25519_unpack_negative_vartime(&P, pk)) {
        return -1;
    }

    ge25519_neg_full(&P);
    curve25519_neg(P.x, P.x);
    ge25519_pack(res, &P);
    return 0;
}

int
ed25519_scalarmult_pure (ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk) {
    bignum256modm a = {0};
    ge25519 ALIGN(16) A, P;

    expand256_modm(a, sk, 32);

    if (!ge25519_unpack_negative_vartime(&P, pk)) {
        return -1;
    }

    ge25519_scalarmult(&A, &P, a);
    memzero(&a, sizeof(a));
    curve25519_neg(A.x, A.x);
    ge25519_pack(res, &A);
    return 0;
}

int
ed25519_cosi_combine_two_publickeys(ed25519_public_key res, CONST ed25519_public_key pk1, CONST ed25519_public_key pk2) {
    ge25519 P = {0};
    ge25519_pniels sump = {0};
    ge25519_p1p1 sump1 = {0};

    if (!ge25519_unpack_negative_vartime(&P, pk1)) {
        return -1;
    }
    ge25519_full_to_pniels(&sump, &P);

    if (!ge25519_unpack_negative_vartime(&P, pk2)) {
        return -1;
    }
    ge25519_pnielsadd_p1p1(&sump1, &P, &sump, 0);
    ge25519_p1p1_to_partial(&P, &sump1);
    curve25519_neg(P.x, P.x);
    ge25519_pack(res, &P);
    return 0;
}