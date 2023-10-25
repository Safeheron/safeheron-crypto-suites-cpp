#ifndef SAFEHERON_CRYPTO_ZKP_RANGE_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_RANGE_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace range_proof{

/**
 * @deprecated
 *
 * @brief This protocol is a zero knowledge proof on Paillier Encryption in Range.
 *
 * SetUp: s = (N_tilde, h1, h2), which is Strong RSA Assumption.
 * Statement: δ = (c, N, q), where N = pail_pub.n()
 * Witness:   ω = (x, r) where x in (0, q), r in ZN*
 * Prove relation: c = Enc(N, x, r) and x in (-q^3, q^3)
 *
 * Completeness for x in (0, q)
 * Soundness for x in (-q^3, q^3)
 *
 * Reference
 * - Appendix A.1 in [GG18](https://eprint.iacr.org/2019/114.pdf)
 */

class AliceRangeProof {
public:
    safeheron::bignum::BN z_;
    safeheron::bignum::BN u_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN s1_;
    safeheron::bignum::BN s2_;
    std::string salt_;

public:
    AliceRangeProof(){};

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const safeheron::bignum::BN &q, const safeheron::bignum::BN &N, const safeheron::bignum::BN &g, const safeheron::bignum::BN &N_tilde, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2, const safeheron::bignum::BN &c, const safeheron::bignum::BN &m, const safeheron::bignum::BN &r);
    bool Verify(const safeheron::bignum::BN &q, const safeheron::bignum::BN &N, const safeheron::bignum::BN &g, const safeheron::bignum::BN &N_tilde, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2, const safeheron::bignum::BN &c) const;

    bool ToProtoObject(safeheron::proto::AliceRangeProof &pail_proof) const;
    bool FromProtoObject(const safeheron::proto::AliceRangeProof &pail_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_RANGE_PROOF_H
