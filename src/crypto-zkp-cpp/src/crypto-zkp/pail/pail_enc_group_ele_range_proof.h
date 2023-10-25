#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_GROUP_RANGE_3_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_GROUP_RANGE_3_PROOF_H

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
 * Statement: δ = (C, N0, N0Sqr, l, varepsilon, X, q, g)
 * Witness:   ω = (x, rho) where x in (0, q), r in ZN*
 * Prove relation:
 *      - C = (1+N0)^x * rho^N0 mod N0^2
 *      - X = g^x
 *      - x in ( -2^(l+varepsilon), 2^(l+varepsilon) )
 *
 * Completeness for x in (0, q). Note that there is a negligible probability of failure for the honest prover (when
 * |alpha| > 2^(l+varepsilon) - q * 2^l - which  happens with negligible probability - it might happen that |z1| > 2^(l+varepsilon) )
 *
 * Soundness for x in ( -2^(l+varepsilon), 2^(l+varepsilon) )
 *
 * Reference
 * - Section C.2 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 * - Section 3.3 proof in phase 5 in [GG20](https://eprint.iacr.org/2020/540.pdf)
 */

struct PailEncGroupEleRangeStatement {
    safeheron::bignum::BN C_; // c = Enc(N0, x, r)
    safeheron::bignum::BN N0_; // N0 = pail_pub.n()
    safeheron::bignum::BN N0Sqr_; // N0Sqr = N0 * N0
    safeheron::bignum::BN q_;
    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint g_;
    uint32_t l_;
    uint32_t varepsilon_;
    PailEncGroupEleRangeStatement(safeheron::bignum::BN C,
                                  safeheron::bignum::BN N0,
                                  safeheron::bignum::BN N0Sqr,
                                  safeheron::bignum::BN q,
                                  const safeheron::curve::CurvePoint &X,
                                  const safeheron::curve::CurvePoint &g,
                                  const uint32_t l,
                                  const uint32_t varepsilon): C_(std::move(C)), N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), q_(std::move(q)), X_(X), g_(g), l_(l), varepsilon_(varepsilon){}
};

struct PailEncGroupEleRangeSetUp{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailEncGroupEleRangeSetUp(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailEncGroupEleRangeWitness {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN rho_;
    PailEncGroupEleRangeWitness(safeheron::bignum::BN x,
                         safeheron::bignum::BN rho):x_(std::move(x)), rho_(std::move(rho)){}
};

class PailEncGroupEleRangeProof {
public:
    safeheron::bignum::BN S_;
    safeheron::bignum::BN A_;
    safeheron::curve::CurvePoint Y_;
    safeheron::bignum::BN D_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN z3_;
    std::string salt_;

    PailEncGroupEleRangeProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailEncGroupEleRangeSetUp &setup, const PailEncGroupEleRangeStatement &statement, const PailEncGroupEleRangeWitness &witness);
    bool Verify(const PailEncGroupEleRangeSetUp &setup, const PailEncGroupEleRangeStatement &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncGroupEleRangeProof &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncGroupEleRangeProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_GROUP_RANGE_3_PROOF_H
