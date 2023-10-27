#ifndef SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V2_H
#define SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V2_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace heg{

/** @brief Homomorphic ElGamal Encryption Proof.
 *
 * Statement: δ = (G, V, R, A, B), where:
 * Witness:   ω = (s, l)
 * Prove relation: V = sR + lG and B=lA
 *
 *
 * Reference
 * - Section 4.3 in [GG18](https://eprint.iacr.org/2019/114.pdf)
 * - Section 3.3 proof in phase 6 in [GG20](https://eprint.iacr.org/2020/540.pdf)
 */

struct HEGStatement_V2 {
    curve::CurvePoint G_;
    curve::CurvePoint V_;
    curve::CurvePoint R_;
    curve::CurvePoint A_;
    curve::CurvePoint B_;
    safeheron::bignum::BN ord_;
    HEGStatement_V2() {}
    HEGStatement_V2(const curve::CurvePoint &G,
                    const curve::CurvePoint &V,
                    const curve::CurvePoint &R,
                    const curve::CurvePoint &A,
                    const curve::CurvePoint &B,
                    const safeheron::bignum::BN ord): G_(G), V_(V), R_(R), A_(A), B_(B), ord_(ord){}
};

struct HEGWitness_V2 {
    safeheron::bignum::BN s_;
    safeheron::bignum::BN l_;
    HEGWitness_V2() {}
    HEGWitness_V2(safeheron::bignum::BN r, safeheron::bignum::BN x):s_(std::move(r)), l_(std::move(x)){}
};

class HEGProof_V2 {
public:
    curve::CurvePoint Alpha_;
    curve::CurvePoint Beta_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN u_;
    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const HEGStatement_V2 &delta, const HEGWitness_V2 &witness);
    void ProveWithR(const HEGStatement_V2 &delta, const HEGWitness_V2 &witness, const safeheron::bignum::BN &s1_lt_curveN, const safeheron::bignum::BN &s2_lt_curveN);
    bool Verify(const HEGStatement_V2 &delta)const;

    bool ToProtoObject(safeheron::proto::HEGProof_V2 &hegProof) const;
    bool FromProtoObject(const safeheron::proto::HEGProof_V2 &hegProof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V2_H
