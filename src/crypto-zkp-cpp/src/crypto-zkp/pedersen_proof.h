#ifndef SAFEHERON_CRYPTO_ZKP_PEDERSEN_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PEDERSEN_PROOF_H

#include <string>
#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace pedersen_proof{

/** @brief A player outputs T = sigma*G + l*H and prove that he knows sigma, l satisfy the above relationship.
 *
 * Statement: δ = (G, H, T), where:
 * Witness:   ω = (sigma, l)
 * Prove relation: T = sigma*G + l*H
 *
 * Reference
 * - Section 3.3 proof in phase 3 in [GG20](https://eprint.iacr.org/2020/540.pdf)
 */

struct PedersenWitness {
    safeheron::bignum::BN sigma_;
    safeheron::bignum::BN l_;
    PedersenWitness() {}
    PedersenWitness(safeheron::bignum::BN sigma, safeheron::bignum::BN l):sigma_(std::move(sigma)), l_(std::move(l)){}
};

struct PedersenStatement{
    curve::CurvePoint G_;
    curve::CurvePoint H_;
    curve::CurvePoint T_; // T = sigma*G + l*H
    PedersenStatement() {}
    PedersenStatement(const curve::CurvePoint &G, const curve::CurvePoint &H, const curve::CurvePoint &T): G_(G), H_(H), T_(T){}
};


class PedersenProof {
public:
    curve::CurvePoint Alpha_;
    safeheron::bignum::BN t_;
    safeheron::bignum::BN u_;
    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PedersenStatement &statement, const PedersenWitness &witness);
    void ProveWithR(const PedersenStatement &statement, const PedersenWitness &witness, const safeheron::bignum::BN &a_lt_curveN, const safeheron::bignum::BN &b_lt_curveN);
    bool Verify(const PedersenStatement &statement)const;

    bool ToProtoObject(safeheron::proto::PedersenProof &pedersen_proof) const;
    bool FromProtoObject(const safeheron::proto::PedersenProof &pedersen_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_PEDERSEN_PROOF_H
