/**
 * IETF 8709
 * Ed25519 and Ed448 Public Key Algorithms for the Secure Shell (SSH) Protocol
 */

#ifndef SFEHERON_CURVE_EdDSA_H
#define SFEHERON_CURVE_EdDSA_H

#include "curve.h"
#include "crypto-bn/bn.h"

namespace safeheron{
namespace curve {
namespace eddsa {

/**
 * Sign a message with a secret key.
 * @param[in] c_type type of elliptic curve.
 * @param[in] priv secret key
 * @param[in] pub public key
 * @param[in] msg message
 * @param[in] len length of message
 * @return signature in bytes.
 */
std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &secret,
                 const CurvePoint &pub,
                 const uint8_t *msg, size_t len);

/**
 * Sign a message with a private key.
 * @param[in] c_type type of elliptic curve.
 * @param[in] priv private key
 * @param[in] msg message
 * @param[in] len length of message
 * @return signature in bytes.
 */
std::string Sign(const CurveType c_type,
                 const safeheron::bignum::BN &priv,
                 const uint8_t *msg, size_t len);

/**
 * Verify a signature.
 * @param[in] c_type type of elliptic curve.
 * @param[in] pub public key
 * @param[in] sig signature
 * @param[in] msg message
 * @param[in] len length of message
 * @return true on success, false on error.
 */
bool Verify(const CurveType c_type,
            const CurvePoint &pub,
            const uint8_t *sig,
            const uint8_t *msg, size_t len);

};
};
};

#endif //SFEHERON_CURVE_EdDSA_H
