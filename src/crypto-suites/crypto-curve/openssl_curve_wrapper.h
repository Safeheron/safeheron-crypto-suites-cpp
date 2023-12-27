#ifndef SAFEHERON_OPENSSL_CURVE_WRAPPER_H_
#define SAFEHERON_OPENSSL_CURVE_WRAPPER_H_

#include "crypto-suites/crypto-bn/bn.h"

struct ec_group_st;
struct ec_point_st;

namespace safeheron{
namespace _openssl_curve_wrapper
{
    /**
     * Encode the elliptic point to bytes. The function will fail while the point is infinity.
     * @param[in] grp the pointer to the elliptic curve group information.
     * @param[in] pub elliptic point
     * @param[out] pub_bytes compressed public key bytes or full public key bytes.
     * @param[out] pub_bytes_len length of pub_bytes.
     *      For full pub key( 0x04 + x + y ),        pub_bytes_len = 1 + 2 * coordinate_len.
     *      For compressed pub key( 0x02/0x03 + x ), pub_bytes_len = 1 + coordinate_len.
     *      Refer to section 2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion in "SEC 1: Elliptic Curve Cryptography"(https://secg.org/sec1-v2.pdf)
     * @param[in] compress encode in compressed format if "compress" flag is set true.
     * @return
     *      @retval 0  success;
     *      @retval <0 failure;
     * @warning Failed while the point is infinity.
     */
    int encode_ec_point(const ec_group_st* grp, const ec_point_st *pub, uint8_t* pub_bytes, int pub_bytes_len, bool compress);

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