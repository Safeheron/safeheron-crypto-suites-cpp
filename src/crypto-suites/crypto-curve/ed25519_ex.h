#ifndef SAFEHERON_CURVE_ED25519_EX_H
#define SAFEHERON_CURVE_ED25519_EX_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "third_party/ed25519-donna/ed25519.h"

/**
 * Multiplication with base point on curve Ed25519: pk = G * sk
 * @param[in] sk
 * @param[out] pk
 */
void ed25519_publickey_pure(const ed25519_secret_key sk, ed25519_public_key pk);

/**
 * Get negative of a point: res = -pk
 * @param[out] res
 * @param[in] pk
 * @return 0 on success, -1 on error.
 */
int ed25519_publickey_neg(ed25519_public_key res, const ed25519_public_key pk);

/**
 * Multiplication on curve: res = pk * sk
 * @param[out] res
 * @param[in] sk
 * @param[in] pk
 * @return 0 on success, -1 on error.
 */
int ed25519_scalarmult_pure(ed25519_public_key res, const ed25519_secret_key sk, const ed25519_public_key pk);

/**
 * Addition on curve: res = pk1 + pk2
 * @param[out] res
 * @param[in] pk1
 * @param[in] pk2
 * @return 0 on success, -1 on error.
 */
int ed25519_cosi_combine_two_publickeys(ed25519_public_key res, CONST ed25519_public_key pk1, CONST ed25519_public_key pk2);

#if defined(__cplusplus)
}
#endif

#endif //SAFEHERON_CURVE_ED25519_EX_H
