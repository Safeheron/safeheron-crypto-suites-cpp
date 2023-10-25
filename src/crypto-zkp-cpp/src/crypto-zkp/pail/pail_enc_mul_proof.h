#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_ENC_MUL_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_ENC_MUL_PROOF_H

#include <string>
#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "../proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace pail {

/**
 * @brief This protocol is a zero knowledge proof on Paillier Encryption in Range.
 *
 * Statement: δ = (N, X, Y , C)
 * Witness:   ω = (x, rho, rho_x)
 * Prove relation:
 *      - (1 + N)^x * rho_x^N = X mod N^2
 *      - Y^x * rho^N = C mod N^2
 *
 * Reference
 * - Section C.6(Figure 29) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct PailEncMulStatement {
    safeheron::bignum::BN N_;
    safeheron::bignum::BN NSqr_;
    safeheron::bignum::BN X_;
    safeheron::bignum::BN Y_;
    safeheron::bignum::BN C_;
    safeheron::bignum::BN q_;
    PailEncMulStatement(safeheron::bignum::BN N,
                        safeheron::bignum::BN NSqr,
                        safeheron::bignum::BN X,
                        safeheron::bignum::BN Y,
                        safeheron::bignum::BN C,
                        safeheron::bignum::BN q): N_(std::move(N)), NSqr_(std::move(NSqr)), X_(std::move(X)), Y_(std::move(Y)), C_(std::move(C)), q_(std::move(q)){}
};

struct PailEncMulWitness {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN rho_;
    safeheron::bignum::BN rho_x_;
    PailEncMulWitness(safeheron::bignum::BN x,
                      safeheron::bignum::BN rho,
                      safeheron::bignum::BN rho_x):x_(std::move(x)), rho_(std::move(rho)), rho_x_(std::move(rho_x)){}
};

class PailEncMulProof {
public:
    safeheron::bignum::BN A_;
    safeheron::bignum::BN B_;
    safeheron::bignum::BN z_;
    safeheron::bignum::BN u_;
    safeheron::bignum::BN v_;
    std::string salt_;

    PailEncMulProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailEncMulStatement &statement, const PailEncMulWitness &witness);
    bool Verify(const PailEncMulStatement &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncMulProof &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncMulProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_ENC_MUL_PROOF_H
