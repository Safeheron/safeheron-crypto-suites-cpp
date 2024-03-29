#include <openssl/ec.h>
#include "crypto-suites/exception/safeheron_exceptions.h"
#include "crypto-suites/crypto-bn/rand.h"
#include "crypto-suites/crypto-encode/base64.h"
#include "crypto-suites/crypto-curve/curve.h"
#include "crypto-suites/crypto-curve/ecdsa.h"
#include "crypto-suites/crypto-curve/openssl_curve_wrapper.h"
#include "crypto-suites/common/custom_assert.h"

using std::string;
using safeheron::bignum::BN;
using safeheron::curve::Curve;
using safeheron::curve::CurvePoint;
using safeheron::curve::CurveType;
using safeheron::exception::LocatedException;
using safeheron::exception::OpensslException;

namespace safeheron{
namespace curve {
namespace ecdsa {

bool RecoverPublicKey(safeheron::curve::CurvePoint &pub, safeheron::curve::CurveType c_type, const safeheron::bignum::BN &h, const safeheron::bignum::BN &r, const safeheron::bignum::BN &s, uint32_t recovery_id) {
#if ENABLE_STARK
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )){
#else
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 )){
#endif //ENABLE_STARK
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )");
    }

    const safeheron::curve::Curve *curv = safeheron::curve::GetCurveParam(c_type);
    // For curve Secp256k1, STARK, Secp256r1(P256), recovery_id \in {0, 1, 2, 3}
    uint8_t enum_recovery_id = (curv->h + 1) * 2;
    // recovery_id in [0, enum_recovery_id)
    if(recovery_id >= enum_recovery_id) return false;
    // A set LSB signifies that the y-coordinate is odd
    bool is_y_odd = recovery_id & 1;
    // get j from recovery_id
    bool j = recovery_id >> 1; // j \in {0, 1}
    if ((j == 1) && (r >= (curv->p % curv->n))) return false;

    // Refer to 4.1.6 Public Key Recovery Operation in [sec1-v2](https://www.secg.org/sec1-v2.pdf).
    // Given j and parity of y-coordinate of Pub
    // x = r + j*n
    BN x = r + curv->n * j;
    // compute R
    CurvePoint R;
    bool ok = R.PointFromX(x, is_y_odd, c_type);
    if (!ok) return false;
    // check n * R  is infinity.
    const CurvePoint expected_infinity = R * curv->n;
    if (!expected_infinity.IsInfinity()) return false;
    // Compute r^{-1}
    const BN r_inv = r.InvM(curv->n);
    const BN& e = h;
    // Q = r^{−1} * (sR − eG)
    pub = (R * s - curv->g * e) * r_inv;
    return true;
}

bool RecoverPublicKey(safeheron::curve::CurvePoint &pub, const CurveType c_type, const uint8_t *sig64, uint32_t sig_len, const uint8_t *digest32, uint32_t digest32_len, uint32_t recovery_id){
    BN m = BN::FromBytesBE(digest32, digest32_len);
    BN r = BN::FromBytesBE(sig64, 32);
    BN s = BN::FromBytesBE(sig64 + 32, 32);
    return RecoverPublicKey(pub, c_type, m , r , s, recovery_id);
}

bool VerifyPublicKey(const safeheron::curve::CurvePoint &expected_pub, safeheron::curve::CurveType c_type, const safeheron::bignum::BN &h, const safeheron::bignum::BN &r, const safeheron::bignum::BN &s, uint32_t recovery_id){
#if ENABLE_STARK
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )){
#else
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 )){
#endif //ENABLE_STARK
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )");
    }
    safeheron::curve::CurvePoint pub;
    bool ok = RecoverPublicKey(pub, c_type, h, r, s, recovery_id);
    if (!ok) return false;
    return pub == expected_pub;
}

bool VerifyPublicKey(const CurvePoint &pub, const CurveType c_type,
                     const uint8_t *sig64, uint32_t sig_len,
                     const uint8_t *digest32, uint32_t digest32_len,
                     uint32_t recovery_id) {
#if ENABLE_STARK
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )){
#else
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 )){
#endif //ENABLE_STARK
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )");
    }
    BN m = BN::FromBytesBE(digest32, digest32_len);
    BN r = BN::FromBytesBE(sig64, 32);
    BN s = BN::FromBytesBE(sig64 + 32, 32);
    return VerifyPublicKey(pub, c_type, m, r, s, recovery_id);
}

void Sign(const CurveType c_type, const BN &priv, const uint8_t *digest32, uint8_t *sig64){
    uint8_t recovery_id;
    Sign(recovery_id, c_type, priv, digest32, sig64);
}

void Sign(uint8_t &recovery_id, const CurveType c_type, const BN &priv, const uint8_t *digest32, uint8_t *sig64){
#if ENABLE_STARK
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )){
#else
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 )){
#endif //ENABLE_STARK
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )");
    }
    //truncate digest32 to 32 bytes
    uint8_t digest_cut[32];
    memcpy(digest_cut, digest32, 32);
    BN z = BN::FromBytesBE(digest_cut, 32);

    const Curve *curv = safeheron::curve::GetCurveParam(c_type);
    const BN& n = curv->n;
    const CurvePoint& g = curv->g;
    //generate k, r
    BN r, k, s;
    BN half_n = curv->n >> 1;
    while (r.IsZero() || s.IsZero()) {
        k = safeheron::rand::RandomBNLt(n);
        CurvePoint R = g * k;
        r = R.x() % n;
        s = (k.InvM(n) * (z + r * priv)) % n;
        // Recovery ID(binary format): 000000xy
        // x(Compare R.x and q):
        //     - 0 j = 0 (R.x < q)
        //     - 1 j = 1 (R.x > q)
        // y(parity of y-coordinate of Pub):
        //     - 0 y-coordinate of R is even
        //     - 1 y-coordinate of R is odd
        recovery_id = (R.y().IsOdd() ? 1 : 0) |     // is_y_odd
                                  ((R.x() != r) ? 2 : 0);       // is_second_key
        if (s > half_n){
            s = curv->n - s;
            recovery_id ^= 1;
        }
    }
    r.ToBytes32BE(sig64);
    s.ToBytes32BE(sig64+32);
}

bool Verify(const CurveType c_type, const CurvePoint &pub, const uint8_t *digest32, const uint8_t *sig64){
#if ENABLE_STARK
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )){
#else
    if(( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 )){
#endif //ENABLE_STARK
        throw LocatedException(__FILE__, __LINE__, __FUNCTION__, -1, "( c_type != CurveType::SECP256K1 ) && (c_type != CurveType::P256 ) && (c_type != CurveType::STARK )");
    }
    if(c_type != pub.GetCurveType()) return false;
    const Curve *curv = safeheron::curve::GetCurveParam(c_type);
    const CurvePoint& g = curv->g;
    const BN& n = curv->n;

    uint8_t digest_cut[32];
    memcpy(digest_cut, digest32, 32);
    BN z = BN::FromBytesBE(digest_cut, 32);

    // check n * pub  is infinity.
    const CurvePoint expected_infinity = pub * curv->n;
    bool ok = expected_infinity.IsInfinity();
    if (!ok) return false;

    // pub is not infinity
    ok = !pub.IsInfinity();
    if (!ok) return false;

    // refer to https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm
    uint8_t r_part[32], s_part[32];
    memcpy(r_part, sig64, 32);
    memcpy(s_part, sig64+32, 32);
    BN r = BN::FromBytesBE(r_part, 32);
    BN s = BN::FromBytesBE(s_part, 32);

    // r < n, s < n
    ok = (r < curv->n) && (s < curv->n);
    if (!ok) return false;

    BN u1 = (z * s.InvM(n)) % n;
    BN u2 = (r * s.InvM(n)) % n;

    CurvePoint P = g * u1 + pub * u2;
    BN xp = (P.x()) % n;
    return r == xp;
}

bool Sig64ToDer(const uint8_t *sig64, uint8_t *der)
{
    ASSERT_THROW(sig64 && der);
    bool ret = 0;
    int der_len = 0;
    BIGNUM* bn_r = nullptr;
    BIGNUM* bn_s = nullptr;
    ECDSA_SIG* ecdsa_sig = nullptr;
    unsigned char* p = nullptr;

    if (!sig64 || !der) {
        return false;
    }

    if (!(bn_r = BN_new()) ||
        !(bn_s = BN_new())) {
        ret = false;
        goto err;
    }

    if (!BN_bin2bn(sig64, 32, bn_r) ||
        !BN_bin2bn(sig64 + 32, 32, bn_s)) {
        ret = false;
        goto err;
    }

    if (!(ecdsa_sig = ECDSA_SIG_new()) ||
        (ret = ECDSA_SIG_set0(ecdsa_sig, bn_r, bn_s)) != 1) {
        ret = false;
        goto err;
    }

    p = der;
    if ((ret = i2d_ECDSA_SIG(ecdsa_sig, &p)) <= 0) {
        ret = false;
        goto err;
    }

    ret = true;

    err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    if (bn_s) {
        BN_free(bn_s);
        bn_s = nullptr;
    }
    if (bn_r) {
        BN_free(bn_r);
        bn_r = nullptr;
    }
    return ret;
}

bool DerToSig64(const uint8_t *der, size_t der_len, uint8_t sig64[64])
{
    bool ret = 0;
    int r_len = 0;
    int s_len = 0;
    uint8_t r[32] = {0};
    uint8_t s[32] = {0};
    ECDSA_SIG* ecdsa_sig = nullptr;
    const BIGNUM* bn_r = nullptr;
    const BIGNUM* bn_s = nullptr;
    const unsigned char* p = nullptr;

    if (!der || der_len <= 0) {
        return false;
    }

    p = der;
    if (!d2i_ECDSA_SIG(&ecdsa_sig, &p, der_len)) {
        return false;
    }

    if (!(bn_r = ECDSA_SIG_get0_r(ecdsa_sig)) ||
        !(bn_s = ECDSA_SIG_get0_s(ecdsa_sig))) {
        ret = false;
        goto err;
    }

    if ((r_len = BN_bn2bin(bn_r, r)) <= 0 ||
        r_len > 32) {
        ret = false;
        goto err;
    }
    if ((s_len = BN_bn2bin(bn_s, s)) <= 0 ||
        s_len > 32) {
        ret = false;
        goto err;
    }

    memcpy(sig64 + (32-r_len), r, r_len);
    memcpy(sig64 + 32 + (32-s_len), s, s_len);

    ret = true;

    err:
    if (ecdsa_sig) {
        ECDSA_SIG_free(ecdsa_sig);
        ecdsa_sig = nullptr;
    }
    return ret;
}

}
}
}
