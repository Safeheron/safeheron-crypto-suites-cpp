#ifndef SAFEHERON_CRYPTO_ZKP_PAIL_N_PROOF_H
#define SAFEHERON_CRYPTO_ZKP_PAIL_N_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "../proto_gen/zkp.pb.switch.h"
#include "crypto-paillier/pail.h"

namespace safeheron{
namespace zkp {
namespace pail {

/**
 * @brief This protocol is based on the NIZK protocol in https://eprint.iacr.org/2018/057.pdf
 *
 * For parameters iteration = 11, alpha = 6370, see section 3.2 https://eprint.iacr.org/2018/057.pdf for full details.
 */

class PailNProof {
private:
    void GenerateXs(std::vector<safeheron::bignum::BN> &x_arr, const safeheron::bignum::BN &N, uint32_t proof_iters = 11) const;
public:
    // List of y^N mod N
    std::vector<safeheron::bignum::BN> y_N_arr_;
    std::string salt_;

    PailNProof(){};

    void SetSalt(const std::string &salt) { salt_ = salt; }

    void Prove(const safeheron::pail::PailPrivKey &pail_priv, uint32_t proof_iters = 11);
    bool Verify(const safeheron::pail::PailPubKey &pail_pub, uint32_t proof_iters = 11) const;

    bool ToProtoObject(safeheron::proto::PailNProof &pail_proof) const;
    bool FromProtoObject(const safeheron::proto::PailNProof &pail_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //SAFEHERON_CRYPTO_ZKP_PAIL_N_PROOF_H
