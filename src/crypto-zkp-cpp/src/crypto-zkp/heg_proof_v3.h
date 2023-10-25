#ifndef SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V3_H
#define SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V3_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace heg{

/** @brief Homomorphic ElGamal Encryption Proof.
 *
 * Statement: δ = (T, G, H, S, R), where:
 * Witness:   ω = (sigma, l)
 * Prove relation:
 *      - T = sigma * G + l * H
 *      - S = sigma * R
 *
 *
 * Reference
 * - Section 3.3 proof in phase 6 in [GG20](https://eprint.iacr.org/2020/540.pdf)
 */

struct HEGStatement_V3 {
    curve::CurvePoint T_;
    curve::CurvePoint G_;
    curve::CurvePoint H_;
    curve::CurvePoint S_;
    curve::CurvePoint R_;
    safeheron::bignum::BN ord_;
    HEGStatement_V3() {}
    HEGStatement_V3(const curve::CurvePoint &T,
                    const curve::CurvePoint &G,
                    const curve::CurvePoint &H,
                    const curve::CurvePoint &S,
                    const curve::CurvePoint &R,
                    const safeheron::bignum::BN ord): T_(T), G_(G), H_(H), S_(S), R_(R), ord_(ord){}
};

struct HEGWitness_V3 {
    safeheron::bignum::BN sigma_;
    safeheron::bignum::BN l_;
    HEGWitness_V3() {}
    HEGWitness_V3(safeheron::bignum::BN sigma, safeheron::bignum::BN l):sigma_(std::move(sigma)), l_(std::move(l)){}
};

class HEGProof_V3 {
public:
    curve::CurvePoint Alpha_;
    curve::CurvePoint Beta_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN u_;
    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const HEGStatement_V3 &delta, const HEGWitness_V3 &witness);
    void ProveWithR(const HEGStatement_V3 &delta, const HEGWitness_V3 &witness, const safeheron::bignum::BN &a_lt_curveN, const safeheron::bignum::BN &b_lt_curveN);
    bool Verify(const HEGStatement_V3 &delta)const;

    bool ToProtoObject(safeheron::proto::HEGProof_V3 &hegProof) const;
    bool FromProtoObject(const safeheron::proto::HEGProof_V3 &hegProof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_HEG_PROOF_V3_H
