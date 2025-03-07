/**
 * Schnorr:
 * - BIP340: Refer to https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
 * - Legacy: Refer to https://gitlab.com/bitcoin-cash-node/bitcoin-cash-node/-/blob/master/src/secp256k1/src/modules/schnorr/schnorr_impl.h?ref_type=heads
 *
 */

#ifndef SFEHERON_CURVE_SCHNORR_H
#define SFEHERON_CURVE_SCHNORR_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"

namespace safeheron{
namespace curve {
namespace schnorr {

enum class SchnorrPattern: uint32_t {
    Legacy = 0, /**< Legacy Schnorr */
    BIP340 = 1, /**< Schnorr supporting BIP340 */
};

/**
 * The function has_even_y(P), where P is a point for which not is_infinite(P), returns y(P) mod 2 = 0.
 * @param point
 * @return true if is_infinite(P) and  y(P) mod 2 == 0.
 */
bool has_even_y(const safeheron::curve::CurvePoint &point);

/**
 * Sign a message with a private key.
 * @param[in] c_type type of elliptic curve.
 * @param[in] priv private key
 * @param[in] msg message
 * @param[in] len length of message
 * @param[in] pattern
 *     - Legacy: Legacy Schnorr
 *     - BIP340: Schnorr supporting BIP340
 * @return signature in bytes.
 */
std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t msg_len,
                 const std::string &aux,
                 SchnorrPattern pattern);

/**
 * Verify a signature.
 * @param[in] c_type type of elliptic curve.
 * @param[in] pub public key
 * @param[in] sig signature
 * @param[in] msg message
 * @param[in] len length of message
 * @param[in] pattern
 *     - Legacy: Legacy Schnorr
 *     - BIP340: Schnorr supporting BIP340
 * @return true on success, false on error.
 */
bool Verify(const CurveType c_type,
            const CurvePoint &pub,
            const uint8_t *sig,
            const uint8_t *msg, size_t len,
            SchnorrPattern pattern);

};
};
};

#endif //SFEHERON_CURVE_SCHNORR_H
