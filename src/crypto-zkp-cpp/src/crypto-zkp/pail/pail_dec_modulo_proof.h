#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_DEC_MUDULO_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_DEC_MUDULO_PROOF_H

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
 * SetUp: s = (N_tilde, h1, h2), which is Strong RSA Assumption.
 * Statement: δ = (q, N0, C, x)
 * Witness:   ω = (y, rho)
 * Prove relation:
 *      - (1 + N0)^y * rho^N0 = X mod N0^2
 *      - x = y mod q
 *
 * Reference
 * - Section C.6(Figure 30) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */

struct PailDecModuloSetUp{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailDecModuloSetUp(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailDecModuloStatement {
    safeheron::bignum::BN q_;
    safeheron::bignum::BN N0_;
    safeheron::bignum::BN N0Sqr_;
    safeheron::bignum::BN C_;
    safeheron::bignum::BN x_;
    uint32_t l_;
    uint32_t varepsilon_;
    PailDecModuloStatement(safeheron::bignum::BN q,
                           safeheron::bignum::BN N0,
                           safeheron::bignum::BN N0Sqr,
                           safeheron::bignum::BN C,
                           safeheron::bignum::BN x,
                           const uint32_t l,
                           const uint32_t varepsilon):q_(std::move(q)), N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), C_(std::move(C)), x_(std::move(x)), l_(l), varepsilon_(varepsilon){}
};

struct PailDecModuloWitness {
    safeheron::bignum::BN y_;
    safeheron::bignum::BN rho_;
    PailDecModuloWitness(safeheron::bignum::BN y,
                         safeheron::bignum::BN rho):y_(y),rho_(rho){}
};


class PailDecModuloProof {
public:
    safeheron::bignum::BN S_;
    safeheron::bignum::BN T_;
    safeheron::bignum::BN A_;
    safeheron::bignum::BN gamma_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN w_;
    std::string salt_;
public:

    PailDecModuloProof()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailDecModuloSetUp &setup, const PailDecModuloStatement &statement, const PailDecModuloWitness &witness);
    bool Verify(const PailDecModuloSetUp &setup, const PailDecModuloStatement &statement) const;

    bool ToProtoObject(safeheron::proto::PailDecModuloProof &proof) const;
    bool FromProtoObject(const safeheron::proto::PailDecModuloProof &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_DEC_MUDULO_PROOF_H
