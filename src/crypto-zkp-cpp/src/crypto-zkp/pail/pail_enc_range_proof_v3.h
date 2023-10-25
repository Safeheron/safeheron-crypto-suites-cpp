#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_1_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_1_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "../proto_gen/zkp.pb.switch.h"
#include "crypto-paillier/pail.h"

namespace safeheron{
namespace zkp {
namespace pail {

/**
 * @brief This protocol is a zero knowledge proof on Paillier Encryption in Range.
 *
 * Statement: δ = (c, pail_pub, l), where:
 * Witness:   ω = (x, r) where x in (0, l) where l = q/3.
 * Prove relation: c = Enc(pail_pub, x, r) and x in (-q/3, 2q/3)
 *
 * Completeness for x in (0, q/3). Note that there is a negligible probability of failure for the honest prover (when
 * alpha > q^3 - q^2 - which  happens with negligible probability - it might happen that s1 > q3)
 * Soundness for x in (-q/3, 2q/3)
 *
 * Reference
 * - Appendix A in [Lindell'17](https://eprint.iacr.org/2017/552)
 * - Section 1.2.2 in [Boudot '00](https://www.iacr.org/archive/eurocrypt2000/1807/18070437-new.pdf)
 */

struct PailEncRangeStatement_V3 {
    safeheron::bignum::BN c_;
    safeheron::pail::PailPubKey pail_pub_;
    safeheron::bignum::BN l_; // range [-l, 2l]
    PailEncRangeStatement_V3() {}
    PailEncRangeStatement_V3(const safeheron::bignum::BN c,
                             const safeheron::pail::PailPubKey &pail_pub,
                             const safeheron::bignum::BN &l): c_(c), pail_pub_(pail_pub), l_(l){}
};

struct PailEncRangeWitness_V3 {
    safeheron::bignum::BN x_;
    safeheron::bignum::BN r_;
    PailEncRangeWitness_V3() {}
    PailEncRangeWitness_V3(const safeheron::bignum::BN &x, const safeheron::bignum::BN &r):x_(x), r_(r){}
};

struct Z_Struct{
    int32_t j_; // j = 1, 2
    safeheron::bignum::BN masked_x_;
    safeheron::bignum::BN masked_r_;

    safeheron::bignum::BN w1_;
    safeheron::bignum::BN w2_;
    safeheron::bignum::BN r1_;
    safeheron::bignum::BN r2_;
};

class PailEncRangeProof_V3 {
public:
    PailEncRangeProof_V3(){};

    void Prove(const PailEncRangeStatement_V3 &statement, const PailEncRangeWitness_V3 &witness);
    bool Verify(const PailEncRangeStatement_V3 &statement) const;

    bool ToProtoObject(safeheron::proto::PailEncRangeProof_V3 &proof) const;
    bool FromProtoObject(const safeheron::proto::PailEncRangeProof_V3 &proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);

public:
    const static uint32_t SECURITY_PARAMETER = 128;

private:
    std::vector<safeheron::bignum::BN> c1_arr_;
    std::vector<safeheron::bignum::BN> c2_arr_;
    std::vector<Z_Struct> z_arr_;
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_ENCRYPTION_RANGE_1_PROOF_H
