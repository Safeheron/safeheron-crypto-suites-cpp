#ifndef SAFEHERON_CRYPTO_ZKP_LINEAR_COMBINATION_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_LINEAR_COMBINATION_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace linear_combination{

/** @brief Linear Combination Proof.
 *
 * Statement: δ = (V, R, G), where:
 * Witness:   ω = (s, l)
 * Prove relation: V = sR + lG
 *
 *
 * Reference
 * - Section 4.3 in [GG18 Revised in December 2021](https://eprint.iacr.org/2019/114.pdf)
 */

struct LinearCombinationStatement {
    safeheron::curve::CurvePoint V_;
    safeheron::curve::CurvePoint R_;
    safeheron::curve::CurvePoint G_;
    safeheron::bignum::BN ord_;
    LinearCombinationStatement() {}
    LinearCombinationStatement(const curve::CurvePoint &V,
                    const curve::CurvePoint &R,
                    const curve::CurvePoint &G,
                    const safeheron::bignum::BN ord):V_(V), R_(R), G_(G), ord_(ord){}
};

struct LinearCombinationWitness {
    safeheron::bignum::BN s_;
    safeheron::bignum::BN l_;
    LinearCombinationWitness() {}
    LinearCombinationWitness(safeheron::bignum::BN r, safeheron::bignum::BN x):s_(std::move(r)), l_(std::move(x)){}
};

class LinearCombinationProof {
public:
    curve::CurvePoint Alpha_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN u_;
    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const LinearCombinationStatement &delta, const LinearCombinationWitness &witness);
    void ProveWithR(const LinearCombinationStatement &delta, const LinearCombinationWitness &witness, const safeheron::bignum::BN &s1_lt_curveN, const safeheron::bignum::BN &s2_lt_curveN);
    bool Verify(const LinearCombinationStatement &delta)const;

    bool ToProtoObject(safeheron::proto::LinearCombinationProof &linear_combination_proof) const;
    bool FromProtoObject(const safeheron::proto::LinearCombinationProof &linear_combination_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_LINEAR_COMBINATION_PROOF_H
