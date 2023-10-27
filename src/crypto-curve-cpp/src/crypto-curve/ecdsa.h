#ifndef SFEHERON_CURVE_ECDSA_H
#define SFEHERON_CURVE_ECDSA_H

#include "curve.h"
#include "crypto-bn/bn.h"


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
 * @param[out] pub public key.
 * @param[in] c_type type of elliptic curve.
 * @param[in] h a BN object which indicates the hash of the message
 * @param[in] r r of signature.
 * @param[in] s s of signature.
 * @param[in] v correspond to the choice of public key(a curve point).
 * @return true on success, false otherwise.
 */
bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const safeheron::bignum::BN &h,
                      const safeheron::bignum::BN &r,
                      const safeheron::bignum::BN &s,
                      uint32_t v);

/**
 * Recover public key from Ecdsa signature.
 * @param[out] pub public key
 * @param[in] c_type type of elliptic curve.
 * @param[in] sig64 signature
 * @param[in] sig64_len length of signature(it's always 64)
 * @param[in] digest32 digest of message.
 * @param[in] digest32_len length of digest32(it's always 32)
 * @param[in] v choice of public key
 * @return true on success, false otherwise.
 */
bool RecoverPublicKey(safeheron::curve::CurvePoint &pub,
                      safeheron::curve::CurveType c_type,
                      const uint8_t *sig64, uint32_t sig_len,
                      const uint8_t *digest32, uint32_t digest32_len,
                      int v);

/**
 * Verify the public key and signature.
 * @param[in] expected_pub expected public key
 * @param[in] c_type type of elliptic curve.
 * @param[in] h a BN object which indicates the hash of the message
 * @param[in] r r of signature.
 * @param[in] s s of signature.
 * @param[in] v correspond to the choice of public key(a curve point).
 * @return true on success, false otherwise.
 */
bool VerifyPublicKey(const safeheron::curve::CurvePoint &expected_pub,
                     safeheron::curve::CurveType c_type,
                     const safeheron::bignum::BN &h,
                     const safeheron::bignum::BN &r,
                     const safeheron::bignum::BN &s,
                     uint32_t v);

/**
 * Verify the public key and signature.
 * @param[in] pub public key
 * @param[in] c_type type of curve
 * @param[in] sig64 signature
 * @param[in] sig64_len length of signature(it's always 64)
 * @param[in] digest32 digest of message.
 * @param[in] digest32_len length of digest32(it's always 32)
 * @param[in] v choice of public key
 * @return true on success, false otherwise.
 */
bool VerifyPublicKey(const safeheron::curve::CurvePoint &pub,
                     safeheron::curve::CurveType c_type,
                     const uint8_t *sig64, uint32_t sig64_len,
                     const uint8_t *digest32, uint32_t digest32_len,
                     uint32_t v);

};
};
};


#endif //SFEHERON_CURVE_ECDSA_H
