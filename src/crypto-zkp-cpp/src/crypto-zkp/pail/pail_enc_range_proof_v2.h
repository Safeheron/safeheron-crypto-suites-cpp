#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_3_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_3_PROOF_H

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
 * SetUp: s = (N_tilde, s, t), which is Strong RSA Assumption.
 * Statement: δ = (K, N0, N0Sqr, l, varepsilon, q)
 * Witness:   ω = (k, rho) where x in (0, q), r in ZN*
 * Prove relation: K = (1+N0)^k * rho^N0 mod N0^2 and x in (-2^l, 2^l)
 *
 * Completeness for k in (0, q). Note that there is a negligible probability of failure for the honest prover (when
 * |alpha| > 2^(l+varepsilon) - q * 2^l - which  happens with negligible probability - it might happen that |z1| > 2^(l+varepsilon) )
 *
 * Soundness for x in ( -2^(l+varepsilon), 2^(l+varepsilon) )
 *
 * Reference
 * - Section 6.1 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 * - Section 6.2 in [MM01](https://www.iacr.org/archive/crypto2001/21390136.pdf)
 */

struct PailEncRangeStatement_V2 {
    safeheron::bignum::BN K_; // c = Enc(N0, x, r)
    safeheron::bignum::BN N0_; // N0 = pail_pub.n()
    safeheron::bignum::BN N0Sqr_; // N0Sqr = N0 * N0
    safeheron::bignum::BN q_;
    uint32_t l_;
    uint32_t varepsilon_;
    PailEncRangeStatement_V2(safeheron::bignum::BN K,
                             safeheron::bignum::BN N0,
                             safeheron::bignum::BN N0Sqr,
                             safeheron::bignum::BN q,
                             const uint32_t l,
                             const uint32_t varepsilon): K_(std::move(K)), N0_(std::move(N0)), N0Sqr_(std::move(N0Sqr)), q_(std::move(q)), l_(l), varepsilon_(varepsilon){}
};


struct PailEncRangeSetUp_V2{
    safeheron::bignum::BN N_tilde_;
    safeheron::bignum::BN s_;
    safeheron::bignum::BN t_;
    PailEncRangeSetUp_V2(safeheron::bignum::BN N_tilde,
                       safeheron::bignum::BN s,
                       safeheron::bignum::BN t): N_tilde_(std::move(N_tilde)), s_(std::move(s)), t_(std::move(t)){}
};

struct PailEncRangeWitness_V2 {
    safeheron::bignum::BN k_;
    safeheron::bignum::BN rho_;
    PailEncRangeWitness_V2(safeheron::bignum::BN k,
                         safeheron::bignum::BN rho):k_(std::move(k)), rho_(std::move(rho)){}
};

class PailEncRangeProof_V2 {
public:
    safeheron::bignum::BN S_;
    safeheron::bignum::BN A_;
    safeheron::bignum::BN C_;
    safeheron::bignum::BN z1_;
    safeheron::bignum::BN z2_;
    safeheron::bignum::BN z3_;
    std::string salt_;

    PailEncRangeProof_V2()= default;;

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const PailEncRangeSetUp_V2 &setup, const PailEncRangeStatement_V2 &statement, const PailEncRangeWitness_V2 &witness);
    bool Verify(const PailEncRangeSetUp_V2 &setup, const PailEncRangeStatement_V2 &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncRangeProof_V2 &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncRangeProof_V2 &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_3_PROOF_H
