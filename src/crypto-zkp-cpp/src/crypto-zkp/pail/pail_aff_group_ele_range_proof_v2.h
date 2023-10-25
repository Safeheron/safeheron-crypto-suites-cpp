#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_2_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_2_PROOF_H

#include <string>
#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "../proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace pail{

/**
 * @brief This protocol is a zero knowledge proof on Paillier Encryption in Range.
 *
 * SetUp: s = (N_tilde, s, t), which is Strong RSA Assumption.
 * Statement: δ = (N0, N1, C, D, Y, X, q, g, l, l_prime, varepsilon)
 * Witness:   ω = (x, y, rho, rho_y) where x in (0, q), y in (0, q^5) , r in ZN*
 * Prove relation:
 *      - x in ( -2^(l + varepsilon),  2^(l + varepsilon))
 *      - y in range [-2^(l'+varepsilon), 2^(l'+varepsilon)]
 *      - X = g^x
 *      - ( 1 + N1 )^y * rho_y^N1 = Y   mod N1^2
 *      - D = C^x * ( 1 + N0 )^y * rho^N0 mod N0^2
 *
 * Completeness for x in (0, q). Note that the protocol may reject a vaoid statement only if |alpha| >= 2^(l+varepsilon) - q * 2^l
 * or |beta| >= 2^(l' + varepsilon) - q * 2^l'  which  happens with negligible probability.
 *
 * Reference
 * - Section 6.2 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 * - Section 6.3 in [MM01](https://www.iacr.org/archive/crypto2001/21390136.pdf)
 */

// Statement: δ = (N0, N1, C, D, Y, X, q, g, l, l_prime, varepsilon)
struct PailAffGroupEleRangeStatement_V2 {
    safeheron::bignum::BN N0_;
    safeheron::bignum::BN N0Sqr_;
    safeheron::bignum::BN N1_;
    safeheron::bignum::BN N1Sqr_;
    safeheron::bignum::BN C_;
    safeheron::bignum::BN D_;
    safeheron::bignum::BN Y_;
    safeheron::curve::CurvePoint X_; // X = g^x
    safeheron::bignum::BN q_;
    uint32_t l_;
    uint32_t l_prime_;
    uint32_t varepsilon_;
    PailAffGroupEleRangeStatement_V2(safeheron::bignum::BN N0,
                                     safeheron::bignum::BN N0Sqr,
                                     safeheron::bignum::BN N1,
                                     safeheron::bignum::BN N1Sqr,
                                     safeheron::bignum::BN C,
                                     safeheron::bignum::BN D,
                                     safeheron::bignum::BN Y,
                                     const safeheron::curve::CurvePoint &X,
                                     safeheron::bignum::BN q,
                                     uint32_t l,
                                     uint32_t l_prime,
                                     uint32_t varepsilon): N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), N1_(std::move(N1)), N1Sqr_(std::move(N1Sqr)), C_(std::move(C)), D_(std::move(D)), Y_(std::move(Y)), X_(X), q_(std::move(q)), l_(l), l_prime_(l_prime), varepsilon_(varepsilon){}
};

struct PailAffGroupEleRangeSetUp_V2{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailAffGroupEleRangeSetUp_V2(safeheron::bignum::BN N_tilde,
                            safeheron::bignum::BN s,
                            safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailAffGroupEleRangeWitness_V2 {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN y_;
    safeheron::bignum::BN rho_;
    safeheron::bignum::BN rho_y_;
    PailAffGroupEleRangeWitness_V2(safeheron::bignum::BN x,
                              safeheron::bignum::BN y,
                              safeheron::bignum::BN rho,
                              safeheron::bignum::BN rho_y):x_(std::move(x)), y_(std::move(y)), rho_(std::move(rho)), rho_y_(std::move(rho_y)){}
};


class PailAffGroupEleRangeProof_V2 {
public:
    safeheron::bignum::BN S_;
    safeheron::bignum::BN T_;
    safeheron::bignum::BN A_;
    safeheron::curve::CurvePoint Bx_;
    safeheron::bignum::BN By_;
    safeheron::bignum::BN E_;
    safeheron::bignum::BN F_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN z3_;
    safeheron::bignum::BN z4_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN wy_;
    std::string salt_;

    PailAffGroupEleRangeProof_V2()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailAffGroupEleRangeSetUp_V2 &setup, const PailAffGroupEleRangeStatement_V2 &statement, const PailAffGroupEleRangeWitness_V2 &witness);
    bool Verify(const PailAffGroupEleRangeSetUp_V2 &setup, const PailAffGroupEleRangeStatement_V2 &statement) const;

    bool ToProtoObject(safeheron::proto::PailAffGroupEleRangeProof_V2 &proof) const;
    bool FromProtoObject(const safeheron::proto::PailAffGroupEleRangeProof_V2 &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_2_PROOF_H
