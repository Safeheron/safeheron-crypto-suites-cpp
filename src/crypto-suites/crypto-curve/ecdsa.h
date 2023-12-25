#ifndef SFEHERON_CURVE_ECDSA_H
#define SFEHERON_CURVE_ECDSA_H

#include "crypto-suites/crypto-bn/bn.h"
#include "crypto-suites/crypto-curve/curve.h"


namespace safeheron{
namespace curve {
namespace ecdsa {

/**
 * Sign a message.
 * @param[in] c_type type of elliptic curve.
 * @param[in] priv private key.
 * @param[in] digest32 digest of message.
 * @param[out] sig64 signature.
 * @note Note that:
 *  - The signature is encode in 64 bytes;
 *  - The digest is store in 32 bytes;
 */
void Sign(safeheron::curve::CurveType c_type, const safeheron::bignum::BN &priv, const uint8_t *digest32, uint8_t *sig64);

/**
 * Sign a message.
 * @param[in] c_type type of elliptic curve.
 * @param[in] priv private key.
 * @param[in] digest32 digest of message.
 * @param[out] sig64 signature.
 * @param[out] recovery_id, correspond to j and parity of y-coordinate of pub point.  The value range of recovery_id is {0, 1,2,3)
 * and there's also a super rare chance(about 0.000000000000000000000000000000000000373%) that recovery_id is no less than 2.
 * @note Note that:
 *  - The signature is encode in 64 bytes;
 *  - The digest is store in 32 bytes;
 */
void Sign(uint8_t &recovery_id, safeheron::curve::CurveType c_type, const safeheron::bignum::BN &priv, const uint8_t *digest32, uint8_t *sig64);

/**
 * Verify the signature.
 * @param[in] c_type type of elliptic curve.
 * @param[in] pub public key
 * @param[in] digest32 digest of message.
 * @param[in] sig64 signature.
 * @note Note that:
 *  - The signature is encode in 64 bytes;
 *  - The digest is store in 32 bytes;
 * @return true on success, false otherwise.
 */
bool Verify(CurveType cType, const CurvePoint &pub, const uint8_t *digest32, const uint8_t *sig64);

/**
 * Convert the format of signature from 64 bytes to DER
 * @param[in] sig64 signature encoded in 64 bytes.
 * @param[out] der signature encoded in DER
 * @return true on success, false otherwise.
 */
bool Sig64ToDer(const uint8_t *sig64, uint8_t *der);

/**
 * Convert the format of signature from DER to 64 bytes.
 * @param[in] der signature encoded in DER
 * @param[in] der_len
 * @param[out] sig64
 * @return true on success, false otherwise.
  */
bool DerToSig64(const uint8_t *der, size_t der_len, uint8_t sig64[64]);

/**
 * Recover public key from Ecdsa signature.
 * Refer to 4.1.6 Public Key Recovery Operation in [sec1-v2](https://www.secg.org/sec1-v2.pdf).
 * @param[out] pub public key.
 * @param[in] c_type type of elliptic curve.
 * @param[in] h a BN object which indicates the hash of the message
 * @param[in] r r of signature.
 * @param[in] s s of signature.
 * @param[in] recovery_id, correspond to j and parity of y-coordinate of pub point.  The value range of recovery_id is {0, 1,2,3)
 * and there's also a super rare chance(about 0.000000000000000000000000000000000000373%) that recovery_id is no less than 2.
 * @return true on success, false otherwise.
 */
bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const safeheron::bignum::BN &h,
                      const safeheron::bignum::BN &r,
                      const safeheron::bignum::BN &s,
                      uint32_t recovery_id);

/**
 * Recover public key from Ecdsa signature.
 * @param[out] pub public key
 * @param[in] c_type type of elliptic curve.
 * @param[in] sig64 signature
 * @param[in] sig64_len length of signature(it's always 64)
 * @param[in] digest32 digest of message.
 * @param[in] digest32_len length of digest32(it's always 32)
 * @param[in] recovery_id, correspond to j and parity of y-coordinate of pub point.  The value range of recovery_id is {0, 1,2,3)
 * and there's also a super rare chance(about 0.000000000000000000000000000000000000373%) that recovery_id is no less than 2.
 * @return true on success, false otherwise.
 */
bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const uint8_t *sig64, uint32_t sig_len,
                      const uint8_t *digest32, uint32_t digest32_len,
                      uint8_t recovery_id);

/**
 * Verify the public key and signature.
 * @param[in] expected_pub expected public key
 * @param[in] c_type type of elliptic curve.
 * @param[in] h a BN object which indicates the hash of the message
 * @param[in] r r of signature.
 * @param[in] s s of signature.
 * @param[in] recovery_id, correspond to j and parity of y-coordinate of pub point.  The value range of recovery_id is {0, 1,2,3)
 * and there's also a super rare chance(about 0.000000000000000000000000000000000000373%) that recovery_id is no less than 2.
 * @return true on success, false otherwise.
 */
bool VerifyPublicKey(const safeheron::curve::CurvePoint &expected_pub,
                     safeheron::curve::CurveType c_type,
                     const safeheron::bignum::BN &h,
                     const safeheron::bignum::BN &r,
                     const safeheron::bignum::BN &s,
                     uint32_t recovery_id);

/**
 * Verify the public key and signature.
 * @param[in] pub public key
 * @param[in] c_type type of curve
 * @param[in] sig64 signature
 * @param[in] sig64_len length of signature(it's always 64)
 * @param[in] digest32 digest of message.
 * @param[in] digest32_len length of digest32(it's always 32)
 * @param[in] recovery_id, correspond to j and parity of y-coordinate of pub point.  The value range of recovery_id is {0, 1,2,3)
 * and there's also a super rare chance(about 0.000000000000000000000000000000000000373%) that recovery_id is no less than 2.
 * @return true on success, false otherwise.
 */
bool VerifyPublicKey(const safeheron::curve::CurvePoint &pub,
                     safeheron::curve::CurveType c_type,
                     const uint8_t *sig64, uint32_t sig64_len,
                     const uint8_t *digest32, uint32_t digest32_len,
                     uint32_t recovery_id);

};
};
};


#endif //SFEHERON_CURVE_ECDSA_H
