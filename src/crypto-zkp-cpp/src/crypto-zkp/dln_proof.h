#ifndef SAFEHERON_CRYPTO_ZKP_DLN_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_DLN_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "proto_gen/zkp.pb.switch.h"

/**
 * Statement: δ = (N, h1, h2)
 * Witness:   ω = (x, p, q)
 * Prove relation:
 *      - h2 = h1^x % N
 *
 * Remark:
 *      - N = PQ = (2p + 1) (2q + 1)
 * Reference
 * - Section 3.3 in [FO97](https://link.springer.com/chapter/10.1007/BFb0052225)
 * - Section 6.4 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */
namespace safeheron{
namespace zkp {
namespace dln_proof{

class DLNProof {
public:
    std::vector<safeheron::bignum::BN> alpha_arr_;
    std::vector<safeheron::bignum::BN> t_arr_;

    std::string salt_;

    DLNProof(){};

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const safeheron::bignum::BN &N, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q, const safeheron::bignum::BN &x);
    bool Verify(const safeheron::bignum::BN &N, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2) const;

    bool ToProtoObject(safeheron::proto::DLNProof &dln_proof) const;
    bool FromProtoObject(const safeheron::proto::DLNProof &dln_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_DLN_PROOF_H
