#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_MUL_GROUP_RANGE_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_MUL_GROUP_RANGE_PROOF_H

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
 * @warning There are some errors in the zero-knowledge proof (p68, C.6 Figure 32 in MPC-CMP), and I think they are just typographical errors.
 * @brief This protocol is a zero knowledge proof on Paillier Multiplication and Group Element in Range.
 *
 *
 * SetUp: s = (N_tilde, s, t), which is Strong RSA Assumption.
 * Statement: δ = (N0, N0Sqr, C, D, X, l, varepsilon)
 * Witness:   ω = (x, rho) where x in (-2^l, 2^l), rho in ZN*
 * Prove relation:
 *      - D = C^x * rho^N0 mod N0^2
 *      - X = g^x
 *      - x in ( -2^(l+varepsilon), 2^(l+varepsilon) )
 *
 * Reference
 * - Section C.6(Figure 31) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct PailMulGroupEleRangeStatement {
    safeheron::bignum::BN N0_;
    safeheron::bignum::BN N0Sqr_;
    safeheron::bignum::BN C_;
    safeheron::bignum::BN D_;
    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint g_;
    safeheron::bignum::BN q_;
    uint32_t l_;
    uint32_t varepsilon_;
    PailMulGroupEleRangeStatement(safeheron::bignum::BN N0,
                                  safeheron::bignum::BN N0Sqr,
                                  safeheron::bignum::BN C,
                                  safeheron::bignum::BN D,
                                  const safeheron::curve::CurvePoint &X,
                                  const safeheron::curve::CurvePoint &g,
                                  safeheron::bignum::BN q,
                                  uint32_t l,
                                  uint32_t varepsilon): N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), C_(std::move(C)), D_(std::move(D)), X_(X), g_(g), q_(std::move(q)), l_(l), varepsilon_(varepsilon){}
};

struct PailMulGroupEleRangeSetUp{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailMulGroupEleRangeSetUp(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailMulGroupEleRangeWitness {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN rho_;
    PailMulGroupEleRangeWitness(safeheron::bignum::BN x, safeheron::bignum::BN rho):x_(std::move(x)), rho_(std::move(rho)){}
};


class PailMulGroupEleRangeProof {
public:
    safeheron::bignum::BN A_;
    safeheron::curve::CurvePoint B_;
    safeheron::bignum::BN E_;
    safeheron::bignum::BN S_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN w_;
    std::string salt_;

    PailMulGroupEleRangeProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailMulGroupEleRangeSetUp &setup, const PailMulGroupEleRangeStatement &statement, const PailMulGroupEleRangeWitness &witness);
    bool Verify(const PailMulGroupEleRangeSetUp &setup, const PailMulGroupEleRangeStatement &statement) const;

    bool ToProtoObject(safeheron::proto::PailMulGroupEleRangeProof &proof) const;
    bool FromProtoObject(const safeheron::proto::PailMulGroupEleRangeProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_MUL_GROUP_RANGE_PROOF_H
