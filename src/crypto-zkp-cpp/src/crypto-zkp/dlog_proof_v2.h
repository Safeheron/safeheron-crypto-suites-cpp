#ifndef SAFEHERON_CRYPTO_ZKP_DLOG_PROOF_V2_H
#define SAFEHERON_CRYPTO_ZKP_DLOG_PROOF_V2_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace dlog {

/** @brief Schnorr PoK
 *
 * Statement: δ = (X), where:
 * Witness:   ω = (x)
 * Prove relation:
 *      - X = x * G
 *
 * Remark: G is the base point of the elliptic curve group.
 *
 * Reference
 * - Section C.1 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

class DLogProof_V2 {
private:
    void InternalProve(const safeheron::bignum::BN &x, const curve::CurvePoint &g, const safeheron::bignum::BN &order);
    void InternalProveWithR(const safeheron::bignum::BN &x, const curve::CurvePoint &g, const safeheron::bignum::BN &order, const safeheron::bignum::BN &alpha);
    bool InternalVerify(const curve::CurvePoint &X) const;

public:
    curve::CurvePoint A_;
    safeheron::bignum::BN z_;
    const curve::Curve *curv_;
    std::string salt_;

public:
    DLogProof_V2(){curv_ = nullptr;};
    DLogProof_V2(curve::CurveType c_type);

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const safeheron::bignum::BN &x);
    void ProveWithR(const safeheron::bignum::BN &x, const safeheron::bignum::BN &alpha);
    bool Verify(const curve::CurvePoint &X) const;

    void ProveEx(const safeheron::bignum::BN &x, safeheron::curve::CurveType curve_type);
    void ProveWithREx(const safeheron::bignum::BN &x, const safeheron::bignum::BN &alpha, safeheron::curve::CurveType curve_type);

    bool ToProtoObject(safeheron::proto::DLogProof_V2 &dlog_proof) const;
    bool FromProtoObject(const safeheron::proto::DLogProof_V2 &dlog_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_DLOG_PROOF_V2_H
