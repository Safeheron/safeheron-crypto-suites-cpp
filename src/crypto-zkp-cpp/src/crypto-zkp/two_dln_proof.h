#ifndef SAFEHERON_CRYPTO_ZKP_TWO_DLN_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_TWO_DLN_PROOF_H

#include "dln_proof.h"

/**
 * Statement: δ = (N, h1, h2)
 * Witness:   ω = (alpha, beta)
 * Prove relation:
 *      - h2 = h1^alpha mod N
 *      - h1 = h2^beta mod N
 *
 * Reference
 * - Section 3.3 in [FO97](https://link.springer.com/chapter/10.1007/BFb0052225)
 * - Section 6.4 in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */
namespace safeheron{
namespace zkp {
namespace dln_proof{

/**
 * Generate N_tilde with the constraints:
 *
 *      - N_tilde = P * Q
 *      - P = p * 2 + 1
 *      - Q = q * 2 + 1
 *      - h2 = h1^alpha mod N_tilde
 *      - h1 = h2^beta mod N_tilde
 */
void GenerateN_tilde(safeheron::bignum::BN &N_tilde, safeheron::bignum::BN &h1, safeheron::bignum::BN &h2, safeheron::bignum::BN &p, safeheron::bignum::BN &q, safeheron::bignum::BN &alpha, safeheron::bignum::BN &beta);

class TwoDLNProof {
public:
    DLNProof dln_proof_1_;
    DLNProof dln_proof_2_;
    std::string salt_;

    TwoDLNProof(){};

public:
    void SetSalt(const std::string &salt) {
        salt_ = salt;
        dln_proof_1_.SetSalt(salt_);
        dln_proof_2_.SetSalt(salt_);
    }

    void Prove(const safeheron::bignum::BN &N, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q, const safeheron::bignum::BN &alpha, const safeheron::bignum::BN &beta);
    bool Verify(const safeheron::bignum::BN &N, const safeheron::bignum::BN &h1, const safeheron::bignum::BN &h2) const;

    bool ToProtoObject(safeheron::proto::TwoDLNProof &dln_proof) const;
    bool FromProtoObject(const safeheron::proto::TwoDLNProof &dln_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_TWO_DLN_PROOF_H
