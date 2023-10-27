#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_COM_ELGAMAL_COM_RANGE_1_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_COM_ELGAMAL_COM_RANGE_1_PROOF_H

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
 * @brief This protocol is a zero knowledge proof on Range Proof w/ El-Gamal Commitment
 *
 * SetUp: s = (N_tilde, s, t), safe bi-prime N_tilde and Ring-Pedersen s, t in ZN_tilde*
 * Statement: δ = (N0, N0Sqr, C, A, B, g, X, q, l, varepsilon)
 * Witness:   ω = (x, rho, a, b)
 *  - x in (-2^l, 2^l)
 *  - rho in ZN0*
 * Prove relation:
 *  - C = (1+N0)^x * rho^N0 mod N0^2, which is a Paillier Commitment.
 *  - (A, B, X) = ( g^a, g^b, g^(a*b+x) ), which is a El-Gamal Commitment.
 *  - x in (-2^(l + varepsilon), 2^(l + varepsilon))
 *
 * Completeness for k in (0, q). Note that there is a negligible probability of failure for the honest prover (when
 * |alpha| > 2^(l+varepsilon) - q * 2^l - which  happens with negligible probability - it might happen that |z1| > 2^(l+varepsilon) )
 *
 * Reference
 * - Section C.4 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct PailEncElGamalComRangeStatement {
    safeheron::bignum::BN N0_;
    safeheron::bignum::BN N0Sqr_;
    safeheron::bignum::BN C_;
    safeheron::curve::CurvePoint A_; // A = g^a
    safeheron::curve::CurvePoint B_; // A = g^b
    safeheron::curve::CurvePoint X_; // X = g^(a * b + x)
    safeheron::bignum::BN q_;
    uint32_t l_;
    uint32_t varepsilon_;
    PailEncElGamalComRangeStatement(safeheron::bignum::BN N0,
                                    safeheron::bignum::BN N0Sqr,
                                    safeheron::bignum::BN C,
                                    const safeheron::curve::CurvePoint& A,
                                    const safeheron::curve::CurvePoint& B,
                                    const safeheron::curve::CurvePoint& X,
                                    safeheron::bignum::BN q,
                                    const uint32_t l,
                                    const uint32_t varepsilon): N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), C_(std::move(C)), A_(A), B_(B), X_(X), q_(std::move(q)), l_(l), varepsilon_(varepsilon){}
};


struct PailEncElGamalComRangeSetUp{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailEncElGamalComRangeSetUp(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailEncElGamalComRangeWitness {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN rho_;
    safeheron::bignum::BN a_;
    safeheron::bignum::BN b_;
    PailEncElGamalComRangeWitness(safeheron::bignum::BN x,
                         safeheron::bignum::BN rho,
                         safeheron::bignum::BN a,
                         safeheron::bignum::BN b):x_(std::move(x)), rho_(std::move(rho)), a_(std::move(a)), b_(std::move(b)){}
};

class PailEncElGamalComRangeProof {
public:
    safeheron::bignum::BN S_;
    safeheron::bignum::BN D_;
    safeheron::curve::CurvePoint Y_;
    safeheron::curve::CurvePoint Z_;
    safeheron::bignum::BN T_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN z3_;
    std::string salt_;

    PailEncElGamalComRangeProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailEncElGamalComRangeSetUp &setup, const PailEncElGamalComRangeStatement &statement, const PailEncElGamalComRangeWitness &witness);
    bool Verify(const PailEncElGamalComRangeSetUp &setup, const PailEncElGamalComRangeStatement &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncElGamalComRangeProof &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncElGamalComRangeProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_COM_ELGAMAL_COM_RANGE_1_PROOF_H
