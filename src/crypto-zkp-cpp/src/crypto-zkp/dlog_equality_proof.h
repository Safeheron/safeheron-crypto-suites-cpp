#ifndef SAFEHERON_CRYPTO_ZKP_DLOG_EQUALITY_1_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_DLOG_EQUALITY_1_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace dlog_equality{

/**
 * @brief This protocol is a zero knowledge proof of Dlog Equality.
 *
 * Statement: δ = (g, h, X, Y, q), where q = |G|
 * Witness:   ω = ( x )
 * Prove relation:
 *      - g^x = X
 *      - h^x = Y
 *
 * Reference
 * - Appendix C.1 (Figure 22) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct DlogEqualityStatement {
    safeheron::curve::CurvePoint g_;
    safeheron::curve::CurvePoint h_;
    safeheron::curve::CurvePoint X_;
    safeheron::curve::CurvePoint Y_;
    safeheron::bignum::BN q_;
    DlogEqualityStatement(const safeheron::curve::CurvePoint &g,
                             const safeheron::curve::CurvePoint &h,
                             const safeheron::curve::CurvePoint &X,
                             const safeheron::curve::CurvePoint &Y,
                             safeheron::bignum::BN q): g_(g), h_(h), X_(X), Y_(Y), q_(std::move(q)){}
};

class DlogEqualityProof {
public:
    safeheron::curve::CurvePoint A_;
    safeheron::curve::CurvePoint B_;
    safeheron::bignum::BN z_;
    std::string salt_;

    DlogEqualityProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const DlogEqualityStatement &statement, const safeheron::bignum::BN &x);
    bool Verify(const DlogEqualityStatement &statement) const;

    bool ToProtoObject(safeheron::proto::DlogEqualityProof &proof) const;
    bool FromProtoObject(const safeheron::proto::DlogEqualityProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_DLOG_EQUALITY_1_PROOF_H
