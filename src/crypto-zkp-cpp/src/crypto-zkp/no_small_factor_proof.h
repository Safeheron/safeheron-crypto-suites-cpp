#ifndef SAFEHERON_CRYPTO_ZKP_NO_SMALL_FACTOR_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_NO_SMALL_FACTOR_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp{
namespace no_small_factor_proof{

/** @brief The prover proves the RSA modulus N0 has no small factors.
 *
 * SetUp: s = (N_tilde, s, t), which is Strong RSA Assumption.
 * Statement: δ = (N0, l, \varepsilon), where:
 *      - l is suggested to be 256
 *      - \varepsilon is suggested to be 512
 * Witness:   ω = (p, q)
 * Prove relation:
 *      - N0 = pq
 *      - p, q > 2^l
 */

struct NoSmallFactorSetUp{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    NoSmallFactorSetUp(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct NoSmallFactorWitness {
    safeheron::bignum::BN p_;
    safeheron::bignum::BN q_;
    NoSmallFactorWitness() {}
    NoSmallFactorWitness(const safeheron::bignum::BN &p, const safeheron::bignum::BN &q):p_(p), q_(q){}
};

struct NoSmallFactorStatement{
    safeheron::bignum::BN N0_;
    uint32_t l_;
    uint32_t varepsilon_;
    NoSmallFactorStatement() {}
    NoSmallFactorStatement(const safeheron::bignum::BN &N0, uint32_t l, uint32_t varepsilon): N0_(N0), l_(l), varepsilon_(varepsilon){}
};

class NoSmallFactorProof {
public:
    safeheron::bignum::BN P_;
    safeheron::bignum::BN Q_;
    safeheron::bignum::BN A_;
    safeheron::bignum::BN B_;
    safeheron::bignum::BN T_;
    safeheron::bignum::BN sigma_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN w1_;
    safeheron::bignum::BN w2_;
    safeheron::bignum::BN v_;

    std::string salt_;

public:
    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const NoSmallFactorSetUp &setup, const NoSmallFactorStatement &statement, const NoSmallFactorWitness &witness);
    bool Verify(const NoSmallFactorSetUp &setup, const NoSmallFactorStatement &statement)const;

    bool ToProtoObject(safeheron::proto::NoSmallFactorProof &pedersen_proof) const;
    bool FromProtoObject(const safeheron::proto::NoSmallFactorProof &pedersen_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}




#endif //SAFEHERON_CRYPTO_ZKP_NO_SMALL_FACTOR_PROOF_H
