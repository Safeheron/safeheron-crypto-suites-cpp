#ifndef SAFEHERON_CRYPTO_ZKP_HEG_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_HEG_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace heg{

/**
 * @deprecated
 * @brief This is a proof of knowledge that a pair of group elements {D, E}
 * form a valid homomorphic ElGamal encryption (”in the exponent”) using public key Y .
 * (HEG is defined in B. Schoenmakers and P. Tuyls. Practical Two-Party Computation Based on the Conditional Gate)
 * Specifically, the witness is ω = (x, r), the statement is δ = (G, H, Y, D, E).
 * The relation R outputs 1 if D = xH+rY , E = rG (for the case of G=H this is ElGamal)
 *
 *
 * Statement: δ = (G, H, Y, D, E), where:
 * Witness:   ω = (x, r)
 * Prove relation: D = xH + rY and E=rG
 */

struct HomoElGamalWitness {
    safeheron::bignum::BN r_;
    safeheron::bignum::BN x_;
    HomoElGamalWitness() {}
    HomoElGamalWitness(safeheron::bignum::BN r, safeheron::bignum::BN x):r_(std::move(r)), x_(std::move(x)){}
};

struct HomoElGamalStatement {
    curve::CurvePoint G_;
    curve::CurvePoint H_;
    curve::CurvePoint Y_;
    curve::CurvePoint D_;
    curve::CurvePoint E_;
    HomoElGamalStatement() {}
    HomoElGamalStatement(const curve::CurvePoint &G,
                         const curve::CurvePoint &H,
                         const curve::CurvePoint &Y,
                         const curve::CurvePoint &D,
                         const curve::CurvePoint &E): G_(G), H_(H), Y_(Y), D_(D), E_(E){}
};

class HegProof {
public:
    curve::CurvePoint T_;
    curve::CurvePoint A3_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const HomoElGamalStatement &delta, const HomoElGamalWitness &witness);
    void ProveWithR(const HomoElGamalStatement &delta, const HomoElGamalWitness &witness, const safeheron::bignum::BN &s1_lt_curveN, const safeheron::bignum::BN &s2_lt_curveN);
    bool Verify(const HomoElGamalStatement &delta)const;

    bool ToProtoObject(safeheron::proto::HegProof &hegProof) const;
    bool FromProtoObject(const safeheron::proto::HegProof &hegProof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_HEG_PROOF_H
