#ifndef SAFEHERON_CURVE_TYPE_H
#define SAFEHERON_CURVE_TYPE_H

#include <cstdlib>

namespace safeheron{
namespace curve{

/**
 * Curve type
 * - 0, invalid
 * - 1 ~ 2^5-1, short curve
 * - 2^5 ~ 2^6-1, edwards curve
 * - 2^6 ~ 2^6+2^5-1, montgomery curve
 */
enum class CurveType: uint32_t {
    INVALID_CURVE = 0xFFFFFFFF, /**< Invalid Curve. */
    SECP256K1 = 1, /**< Curve Secp256k1 */
    P256 = 2, /**< Curve Secp256r1 */
    STARK = 4,  /**< Curve Stark256v1 */
    ED25519 = 32, /**< Curve Ed25519 */
};

};
};
#endif //SAFEHERON_CURVE_TYPE_H
