#ifndef SAFEHERON_CRYPTO_ZKP_PaillierBlumModulus_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PaillierBlumModulus_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "../proto_gen/zkp.pb.switch.h"

namespace safeheron{
namespace zkp {
namespace pail {

/**
 * @brief This protocol is a zero knowledge proof on Paillier-Blum Modulus.
 *
 * Statement: δ = (N)
 * Witness:   ω = (p, q)
 * Prove relation:
 *      - gcd(N, phi(N)) = 1
 *      - N = p * q
 *      - p, q = 3 mod 4
 *
 * Reference
 * - Section 6.3(Figure 16) in [MPC-CMP](https://eprint.iacr.org/2021/060.pdf)
 */
class PailBlumModulusProof {
public:
    std::vector<safeheron::bignum::BN> x_arr_;
    std::vector<int32_t> a_arr_;
    std::vector<int32_t> b_arr_;
    std::vector<safeheron::bignum::BN> z_arr_;
    safeheron::bignum::BN w_;

    std::string salt_;

    PailBlumModulusProof(){};

    void SetSalt(const std::string &salt) { salt_ = salt; }

    static bool GetQuarticSqrt(const safeheron::bignum::BN &N, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q, const safeheron::bignum::BN &p_inv, const safeheron::bignum::BN &q_inv, const safeheron::bignum::BN &w, const safeheron::bignum::BN &r, safeheron::bignum::BN &root, int32_t &a, int32_t &b ) ;
    void GenerateYs(std::vector<safeheron::bignum::BN> &x_arr, const safeheron::bignum::BN &N, const safeheron::bignum::BN &w, uint32_t proof_iters) const;

    bool Prove(const safeheron::bignum::BN &N, const safeheron::bignum::BN &p, const safeheron::bignum::BN &q);
    bool Verify(const safeheron::bignum::BN &N) const;

    bool ToProtoObject(safeheron::proto::PailBlumModulusProof &dln_proof) const;
    bool FromProtoObject(const safeheron::proto::PailBlumModulusProof &dln_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PaillierBlumModulus_PROOF_H
