#ifndef SAFEHERON_OPENSSL_CURVE_WRAPPER_H_
#define SAFEHERON_OPENSSL_CURVE_WRAPPER_H_

#include "../crypto-bn/bn.h"

struct ec_group_st;
struct ec_point_st;

namespace safeheron{
namespace _openssl_curve_wrapper
{
    /**
     * Encode the elliptic point to bytes.
     * @param[in] grp the pointer to the elliptic curve group information.
     * @param[in] pub elliptic point
     * @param[out] pub_key compressed public key bytes or full public key bytes.
     * @param[in] compress encode in compressed format if "compress" flag is set true.
     * @return 0 on success.
     */
    int encode_ec_point(const ec_group_st* grp, const ec_point_st *pub, uint8_t *pub_key, bool compress);

    /**
     * Sign a digest.
     * @param[in] grp the pointer to the elliptic curve group information.
     * @param[in] priv_key  private key
     * @param[in] digest32 digest of the message
     * @param[out] sig64 signature
     * @note Note that:
     *  - The signature is encode in 64 bytes;
     *  - The digest is store in 32 bytes;
     * @return 0 on success.
     */
    int sign_digest(const ec_group_st* grp, const uint8_t *priv_key, const uint8_t *digest32, uint8_t *sig64);

    /**
     * Verify the signature.
     * @param[in] grp the pointer to the elliptic curve group information.
     * @param[in] pub_key public key
     * @param[in] digest32 digest of the message
     * @param[in] sig64 signature
     * @note Note that:
     *  - The signature is encode in 64 bytes;
     *  - The digest is store in 32 bytes;
     * @return 0 on success.
     */
    int verify_digest(const ec_group_st* grp, const uint8_t *pub_key, const uint8_t *digest32, const uint8_t *sig64);
};
};

#endif //SAFEHERON_OPENSSL_CURVE_WRAPPER_H_