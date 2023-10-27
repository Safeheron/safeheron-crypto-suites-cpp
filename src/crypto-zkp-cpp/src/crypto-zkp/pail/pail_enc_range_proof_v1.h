#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_2_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_2_PROOF_H

#include <string>
#include <utility>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "crypto-paillier/pail.h"
#include "../proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace pail{

/**
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
 * - Section 6.2 in [MM01](https://www.iacr.org/archive/crypto2001/21390136.pdf)
 */

struct PailEncRangeStatement_V1 {
    safeheron::bignum::BN c_; // c = Enc(N, x, r)
    safeheron::bignum::BN N_; // N = pail_pub.n()
    safeheron::bignum::BN N2_; // N2 = N * N
    safeheron::bignum::BN q_; // order of elliptic curve
    PailEncRangeStatement_V1(safeheron::bignum::BN c,
                             safeheron::bignum::BN N,
                             safeheron::bignum::BN N2,
                             safeheron::bignum::BN q): c_(std::move(c)), N_(std::move(N)), N2_(std::move(N2)), q_(std::move(q)){}
};


struct PailEncRangeSetUp_V1{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN h1_;
    safeheron::bignum::BN h2_;
    PailEncRangeSetUp_V1(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN h1,
                       safeheron::bignum::BN h2): N_tilde_(std::move(N_tilde)), h1_(std::move(h1)), h2_(std::move(h2)){}
};

struct PailEncRangeWitness_V1 {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN r_;
    PailEncRangeWitness_V1(safeheron::bignum::BN x,
                         safeheron::bignum::BN r):x_(std::move(x)), r_(std::move(r)){}
};

class PailEncRangeProof_V1 {
public:
    safeheron::bignum::BN z_;
    safeheron::bignum::BN u_;
    safeheron::bignum::BN w_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN s1_;
    safeheron::bignum::BN s2_;
    std::string salt_;

    PailEncRangeProof_V1()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailEncRangeSetUp_V1 &setup, const PailEncRangeStatement_V1 &statement, const PailEncRangeWitness_V1 &witness);
    bool Verify(const PailEncRangeSetUp_V1 &setup, const PailEncRangeStatement_V1 &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncRangeProof_V1 &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncRangeProof_V1 &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_2_PROOF_H
