#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_1_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_1_PROOF_H

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
 * SetUp: s = (N_tilde, h1, h2), which is Strong RSA Assumption.
 * Statement: δ = (c1, c2, X, pail_pub, q)
 * Witness:   ω = (x, y, r) where x in (0, q), y in (0, q^5) , r in ZN*
 * Prove relation:
 *      - X = g^x
 *      - c2 = c1^x * Gamma^y * r^N mod N^2, which means Dec(c2) = Dec(c1) * x + y if c1 and c2 is encrypted by Paillier private key.
 *      - x in (-q^3, q^3)
 *      - y in (-q^7, q^7)
 *
 * Completeness for x in (0, q). Note that there is a negligible probability of failure for the honest prover (when
 * alpha > q^3 - q^2 or t1 > q^7 - q^2  - which  happens with negligible probability - it might happen that s1 > q3 or
 * t1 > q^7)
 *
 * Soundness for:
 *      - x in (-q^3, q^3)
 *
 * Reference
 * - Appendix A.2 in [GG18](https://eprint.iacr.org/2019/114.pdf)
 * - Section 6.3 in [MM01](https://www.iacr.org/archive/crypto2001/21390136.pdf)
 */

struct PailAffGroupEleRangeSetUp_V1{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;
    PailAffGroupEleRangeSetUp_V1(safeheron::bignum::BN N_tilde,
                                 safeheron::bignum::BN h1,
                                 safeheron::bignum::BN h2): N_tilde_(std::move(N_tilde)), h1_(std::move(h1)), h2_(std::move(h2)){}
};

struct PailAffGroupEleRangeStatement_V1 {
    safeheron::bignum::BN c1_;
    safeheron::bignum::BN c2_; // c2 = c1^x * Gamma^y * r^N mod N^2, where y in range [-q^7, q^7]
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::curve::CurvePoint X_; // X = g^x, where x in range [-q^3, q^3]
    safeheron::bignum::BN q_;
    PailAffGroupEleRangeStatement_V1(safeheron::bignum::BN c1,
                                     safeheron::bignum::BN c2,
                                     safeheron::pail::PailPubKey pail_pub,
                                     const safeheron::curve::CurvePoint &X,
                                     safeheron::bignum::BN q): c1_(std::move(c1)), c2_(std::move(c2)), pail_pub_(std::move(pail_pub)), X_(X), q_(std::move(q)){}
};

struct PailAffGroupEleRangeWitness_V1 {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN y_;
    safeheron::bignum::BN r_;
    PailAffGroupEleRangeWitness_V1(safeheron::bignum::BN x,
                                   safeheron::bignum::BN y,
                                   safeheron::bignum::BN r):x_(std::move(x)), y_(std::move(y)), r_(std::move(r)){}
};


class PailAffGroupEleRangeProof_V1 {
public:
    safeheron::curve::CurvePoint u_;
    safeheron::bignum::BN z_;
    safeheron::bignum::BN z_prime_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN v_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN s1_;
    safeheron::bignum::BN s2_;
    safeheron::bignum::BN t1_;
    safeheron::bignum::BN t2_;
    std::string salt_;
public:

    PailAffGroupEleRangeProof_V1()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailAffGroupEleRangeSetUp_V1 &setup, const PailAffGroupEleRangeStatement_V1 &statement, const PailAffGroupEleRangeWitness_V1 &witness);
    bool Verify(const PailAffGroupEleRangeSetUp_V1 &setup, const PailAffGroupEleRangeStatement_V1 &statement) const;

    bool ToProtoObject(safeheron::proto::PailAffGroupEleRangeProof_V1 &proof) const;
    bool FromProtoObject(const safeheron::proto::PailAffGroupEleRangeProof_V1 &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_AFFINE_GROUP_RANGE_1_PROOF_H
