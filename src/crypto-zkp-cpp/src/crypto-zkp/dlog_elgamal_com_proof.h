#ifndef SAFEHERON_CRYPTO_ZKP_DLOG_ELGAMAL_COM_1_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_DLOG_ELGAMAL_COM_1_PROOF_H

#include <string>
#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace dlog_elgamal_com {

/**
 * @brief This protocol is a zero knowledge proof of Dlog with El-Gamal Commitment
 *
 * Statement: δ = (g, L, M, X, Y, h, q)
 * Witness:   ω = (y, lambda)
 * Prove relation:
 *      - L = g^lambda
 *      - M = g^y * X^lambda
 *      - Y = h^y
 *
 * Reference
 * - Appendix C.1 (Figure 24) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct DlogElGamalComStatement {
    safeheron::curve::CurvePoint g_;
    safeheron::curve::CurvePoint L_;
    safeheron::curve::CurvePoint M_;
    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint Y_;
    safeheron::curve::CurvePoint h_;
    safeheron::bignum::BN q_;
    DlogElGamalComStatement(const safeheron::curve::CurvePoint &g,
                            const safeheron::curve::CurvePoint &L,
                            const safeheron::curve::CurvePoint &M,
                            const safeheron::curve::CurvePoint &X,
                            const safeheron::curve::CurvePoint &Y,
                            const safeheron::curve::CurvePoint &h,
                            safeheron::bignum::BN q): g_(g), L_(L), M_(M), X_(X), Y_(Y), h_(h), q_(std::move(q)){}
};

struct DlogElGamalComWitness {
    safeheron::bignum::BN y_;
    safeheron::bignum::BN lambda_;
    DlogElGamalComWitness(safeheron::bignum::BN y,
                          safeheron::bignum::BN lambda):y_(std::move(y)), lambda_(std::move(lambda)){}
};


class DlogElGamalComProof {
public:
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint N_;
    safeheron::curve::CurvePoint B_;
    safeheron::bignum::BN z_;
    safeheron::bignum::BN u_;
    std::string salt_;

    DlogElGamalComProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const DlogElGamalComStatement &statement, const DlogElGamalComWitness &witness);
    bool Verify(const DlogElGamalComStatement &statement) const;

    bool ToProtoObject(safeheron::proto::DlogElGamalComProof &proof) const;
    bool FromProtoObject(const safeheron::proto::DlogElGamalComProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_DLOG_ELGAMAL_COM_1_PROOF_H
